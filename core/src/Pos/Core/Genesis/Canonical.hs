{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | Canonical encoding of 'GenesisData'.

module Pos.Core.Genesis.Canonical
       ( SchemaError(..)
       , tryParseString
       , wrapConstructor
       ) where

import           Universum

import           Control.Lens (_Left)
import           Control.Monad.Except (MonadError (..))
import qualified Data.HashMap.Strict as HM
import qualified Data.Text.Lazy.Builder as Builder (fromText)
import           Data.Time.Units (Millisecond)
import           Data.Typeable (typeRep)
import           Formatting (formatToString)
import qualified Formatting.Buildable as Buildable
import           Serokell.Data.Memory.Units (Byte)
import           Serokell.Util.Base64 (base64F)
import qualified Serokell.Util.Base64 as B64
import           Serokell.Util.Text (readDecimal, readUnsignedDecimal)
import           Text.JSON.Canonical (FromJSON (..), FromObjectKey (..),
                     JSValue (..), ReportSchemaErrors (expected), ToJSON (..),
                     ToObjectKey (..), expectedButGotValue, fromJSObject)

import           Pos.Binary.Class (AsBinary (..))
import           Pos.Crypto (ProxyCert, PublicKey, RedeemPublicKey, Signature,
                     fromAvvmPk, fullProxyCertHexF, fullPublicKeyF,
                     fullSignatureHexF, parseFullProxyCert, parseFullPublicKey,
                     parseFullSignature, redeemPkB64UrlF)

----------------------------------------------------------------------------
-- Primitive standard/3rdparty types
----------------------------------------------------------------------------

data SchemaError = SchemaError
    { seExpected :: !Text
    , seActual   :: !(Maybe Text)
    } deriving (Show)

instance Buildable SchemaError where
    build SchemaError{..} = mconcat
        [ "expected " <> Builder.fromText seExpected
        , case seActual of
            Nothing     -> mempty
            Just actual -> " but got " <> Builder.fromText actual
        ]

instance (Monad m, Applicative m, MonadError SchemaError m) => ReportSchemaErrors m where
    expected expec actual = throwError SchemaError
        { seExpected = fromString expec
        , seActual = fmap fromString actual
        }

instance Monad m => ToJSON m Int32 where
    toJSON = pure . JSNum . fromIntegral

instance Monad m => ToJSON m Word16 where
    toJSON = pure . JSNum . fromIntegral

instance Monad m => ToJSON m Word32 where
    toJSON = pure . JSNum . fromIntegral

instance Monad m => ToJSON m Word64 where
    toJSON = pure . JSString . show

instance Monad m => ToJSON m Integer where
    toJSON = pure . JSString . show

-- We don't need to sort keys in this instance, because rendering
-- takes care of it.
instance (Monad m, ToObjectKey m k, ToJSON m a) => ToJSON m (HashMap k a) where
    toJSON = fmap JSObject . mapM aux . HM.toList
      where
        aux :: (k, a) -> m (String, JSValue)
        aux (k, a) = (,) <$> toObjectKey k <*> toJSON a

instance Monad m => ToJSON m Byte where
    toJSON = toJSON . toInteger

instance Monad m => ToJSON m Millisecond where
    toJSON = toJSON . toInteger

----------------------------------------------------------------------------
-- Our crypto types
----------------------------------------------------------------------------

instance Monad m => ToJSON m PublicKey where
    toJSON = pure . JSString . formatToString fullPublicKeyF

instance Monad m => ToJSON m (ProxyCert w) where
    toJSON = pure . JSString . formatToString fullProxyCertHexF

instance Monad m => ToJSON m (Signature w) where
    toJSON = pure . JSString . formatToString fullSignatureHexF

instance Monad m => ToObjectKey m RedeemPublicKey where
    toObjectKey = pure . formatToString redeemPkB64UrlF

----------------------------------------------------------------------------
-- Our core types
----------------------------------------------------------------------------

instance Monad m => ToJSON m (AsBinary smth) where
    toJSON = pure . JSString . formatToString base64F . getAsBinary

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

tryParseString ::
       forall a m e. (Typeable a, ReportSchemaErrors m, ToString e)
    => (Text -> Either e a)
    -> JSValue
    -> m a
tryParseString parser =
    \case
        JSString str ->
            case parser (toText str) of
                Right res -> pure res
                Left (toString -> err) ->
                    expected typeName (Just $ str <> ", err was: " <> err)
        val -> expectedButGotValue typeName val
  where
    typeName = show $ typeRep (Proxy @a)

wrapConstructor ::
       forall e a m. (Typeable a, ReportSchemaErrors m, ToString e)
    => Either e a
    -> m a
wrapConstructor =
    \case
        Left err ->
            expected typeName (Just $ "error occurred: " <> toString err)
        Right x -> pure x
  where
    typeName = show $ typeRep (Proxy @a)

----------------------------------------------------------------------------
-- External
---------------------------------------------------------------------------

instance (ReportSchemaErrors m) => FromJSON m Int32 where
    fromJSON (JSNum i) = pure . fromIntegral $ i
    fromJSON val       = expectedButGotValue "Int32" val

instance (ReportSchemaErrors m) => FromJSON m Word16 where
    fromJSON (JSNum i) = pure . fromIntegral $ i
    fromJSON val       = expectedButGotValue "Word16" val

instance (ReportSchemaErrors m) => FromJSON m Word32 where
    fromJSON (JSNum i) = pure . fromIntegral $ i
    fromJSON val       = expectedButGotValue "Word32" val

instance (ReportSchemaErrors m) => FromJSON m Word64 where
    fromJSON = tryParseString readUnsignedDecimal

instance (ReportSchemaErrors m) => FromJSON m Integer where
    fromJSON = tryParseString readDecimal

instance (ReportSchemaErrors m, Eq k, Hashable k, FromObjectKey m k, FromJSON m a) =>
         FromJSON m (HashMap k a) where
    fromJSON enc = do
        obj <- fromJSObject enc
        HM.fromList . catMaybes <$> mapM aux obj
      where
        aux :: (String, JSValue) -> m (Maybe (k, a))
        aux (k, a) = knownKeys <$> fromObjectKey k <*> fromJSON a
        knownKeys :: Maybe k -> a -> Maybe (k, a)
        knownKeys Nothing _  = Nothing
        knownKeys (Just k) a = Just (k, a)

instance ReportSchemaErrors m => FromJSON m Byte where
    fromJSON = fmap fromInteger . fromJSON

instance ReportSchemaErrors m => FromJSON m Millisecond where
    fromJSON = fmap fromInteger . fromJSON

----------------------------------------------------------------------------
-- Crypto
----------------------------------------------------------------------------

instance ReportSchemaErrors m => FromJSON m PublicKey where
    fromJSON = tryParseString parseFullPublicKey

instance (Typeable w, ReportSchemaErrors m) => FromJSON m (ProxyCert w) where
    fromJSON = tryParseString parseFullProxyCert

instance (Typeable x, ReportSchemaErrors m) => FromJSON m (Signature x) where
    fromJSON = tryParseString parseFullSignature

instance ReportSchemaErrors m => FromObjectKey m RedeemPublicKey where
    fromObjectKey =
        fmap Just .
        tryParseString (over _Left pretty . fromAvvmPk) .
        JSString

instance ReportSchemaErrors m => FromJSON m (AsBinary smth) where
    fromJSON = fmap AsBinary . tryParseString B64.decode
