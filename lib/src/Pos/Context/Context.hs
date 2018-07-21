{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE TypeFamilies              #-}
{-# LANGUAGE TypeOperators             #-}
{-# OPTIONS -fno-warn-unused-top-binds #-} -- for lenses

-- | Runtime context of node.

module Pos.Context.Context
       ( HasNodeContext(..)
       , HasSscContext(..)
       , NodeContext (..)
       , NodeParams(..)
       , BaseParams(..)
       , TxpGlobalSettings
       , StartTime(..)

       , BlockRetrievalQueueTag
       , BlockRetrievalQueue

       , ConnectedPeers(..)
       ) where

import           Universum

import           Control.Lens (lens, makeLensesWith)
import           Data.Time.Clock (UTCTime)
import           System.Wlog (LoggerConfig)

import           Pos.Block.Slog (HasSlogContext (..), HasSlogGState (..),
                     SlogContext (..))
import           Pos.Block.Types (LastKnownHeader, LastKnownHeaderTag)
import           Pos.Communication.Types (NodeId)
import           Pos.Core (HasPrimaryKey (..), Timestamp)
import           Pos.Core.Reporting (HasMisbehaviorMetrics (..),
                     MisbehaviorMetrics (..))
import           Pos.Infra.DHT.Real.Param (KademliaParams)
import           Pos.Infra.Network.Types (NetworkConfig (..))
import           Pos.Infra.Recovery.Types (RecoveryHeader, RecoveryHeaderTag)
import           Pos.Infra.Shutdown (HasShutdownContext (..),
                     ShutdownContext (..))
import           Pos.Infra.Slotting (HasSlottingVar (..),
                     SimpleSlottingStateVar)
import           Pos.Infra.Slotting.Types (SlottingData)
import           Pos.Infra.StateLock (StateLock, StateLockMetrics)
import           Pos.Infra.Util.JsonLog.Events (MemPoolModifyReason (..))
import           Pos.Launcher.Param (BaseParams (..), NodeParams (..))
import           Pos.Lrc.Context (LrcContext)
import           Pos.Network.Block.RetrievalQueue (BlockRetrievalQueue,
                     BlockRetrievalQueueTag)
import           Pos.Ssc.Types (HasSscContext (..), SscContext)
import           Pos.Txp.Settings (TxpGlobalSettings)
import           Pos.Update.Context (UpdateContext)
import           Pos.Util.Lens (postfixLFields)
import           Pos.Util.UserSecret (HasUserSecret (..), UserSecret)
import           Pos.Util.Util (HasLens (..))

----------------------------------------------------------------------------
-- NodeContext
----------------------------------------------------------------------------

newtype ConnectedPeers = ConnectedPeers { unConnectedPeers :: TVar (Set NodeId) }
newtype StartTime = StartTime { unStartTime :: UTCTime }

data SscContextTag

-- | NodeContext contains runtime context of node.
data NodeContext = NodeContext
    { ncSscContext          :: !SscContext
    -- ^ Context needed for Shared Seed Computation (SSC).
    , ncUpdateContext       :: !UpdateContext
    -- ^ Context needed for the update system
    , ncLrcContext          :: !LrcContext
    -- ^ Context needed for LRC
    , ncSlottingVar         :: !(Timestamp, TVar SlottingData)
    -- ^ Data necessary for 'MonadSlotsData'.
    , ncSlottingContext     :: !SimpleSlottingStateVar
    -- ^ Context needed for Slotting.
    , ncShutdownContext     :: !ShutdownContext
    -- ^ Context needed for Shutdown
    , ncSlogContext         :: !SlogContext
    -- ^ Context needed for Slog.
    , ncStateLock           :: !StateLock
    -- ^ A lock which manages access to shared resources.
    -- Stored hash is a hash of last applied block.
    , ncStateLockMetrics    :: !(StateLockMetrics MemPoolModifyReason)
    -- ^ A set of callbacks for 'StateLock'.
    , ncUserSecret          :: !(TVar UserSecret)
    -- ^ Secret keys (and path to file) which are used to send transactions
    , ncBlockRetrievalQueue :: !BlockRetrievalQueue
    -- ^ Concurrent queue that holds block headers that are to be
    -- downloaded.
    , ncRecoveryHeader      :: !RecoveryHeader
    -- ^ In case of recovery mode this variable holds the latest header hash
    -- we know about, and the node we're talking to, so we can do chained
    -- block requests. Invariant: this mvar is full iff we're in recovery mode
    -- and downloading blocks. Every time we get block that's more
    -- difficult than this one, we overwrite. Every time we process some
    -- blocks and fail or see that we've downloaded this header, we clean
    -- mvar.
    , ncLastKnownHeader     :: !LastKnownHeader
    -- ^ Header of last known block, generated by network (announcement of
    -- which reached us). Should be use only for informational purposes
    -- (status in Daedalus). It's easy to falsify this value.
    , ncLoggerConfig        :: !LoggerConfig
    -- ^ Logger config, as taken/read from CLI.
    , ncNodeParams          :: !NodeParams
    -- ^ Params node is launched with
    , ncStartTime           :: !StartTime
    -- ^ Time when node was started ('NodeContext' initialized).
    , ncTxpGlobalSettings   :: !TxpGlobalSettings
    -- ^ Settings for global Txp.
    , ncConnectedPeers      :: !ConnectedPeers
    -- ^ Set of peers that we're connected to.
    , ncNetworkConfig       :: !(NetworkConfig KademliaParams)
    , ncMisbehaviorMetrics  :: Maybe MisbehaviorMetrics
    }

makeLensesWith postfixLFields ''NodeContext

class HasNodeContext ctx where
    nodeContext :: Lens' ctx NodeContext

instance HasNodeContext NodeContext where
    nodeContext = identity

instance HasSscContext NodeContext where
    sscContext = ncSscContext_L

instance HasSlottingVar NodeContext where
    slottingTimestamp = ncSlottingVar_L . _1
    slottingVar = ncSlottingVar_L . _2

instance HasSlogContext NodeContext where
    slogContext = ncSlogContext_L

instance HasSlogGState NodeContext where
    slogGState = ncSlogContext_L . slogGState

instance HasLens SimpleSlottingStateVar NodeContext SimpleSlottingStateVar where
    lensOf = ncSlottingContext_L

instance HasLens StateLock NodeContext StateLock where
    lensOf = ncStateLock_L

instance HasLens (StateLockMetrics MemPoolModifyReason) NodeContext (StateLockMetrics MemPoolModifyReason) where
    lensOf = ncStateLockMetrics_L

instance HasLens LastKnownHeaderTag NodeContext LastKnownHeader where
    lensOf = ncLastKnownHeader_L

instance HasShutdownContext NodeContext where
    shutdownContext = ncShutdownContext_L

instance HasLens UpdateContext NodeContext UpdateContext where
    lensOf = ncUpdateContext_L

instance HasUserSecret NodeContext where
    userSecret = ncUserSecret_L

instance HasLens RecoveryHeaderTag NodeContext RecoveryHeader where
    lensOf = ncRecoveryHeader_L

instance HasLens ConnectedPeers NodeContext ConnectedPeers where
    lensOf = ncConnectedPeers_L

instance HasLens BlockRetrievalQueueTag NodeContext BlockRetrievalQueue where
    lensOf = ncBlockRetrievalQueue_L

instance HasLens StartTime NodeContext StartTime where
    lensOf = ncStartTime_L

instance HasLens LrcContext NodeContext LrcContext where
    lensOf = ncLrcContext_L

instance HasLens TxpGlobalSettings NodeContext TxpGlobalSettings where
    lensOf = ncTxpGlobalSettings_L

instance {-# OVERLAPPABLE #-}
    HasLens tag NodeParams r =>
    HasLens tag NodeContext r
  where
    lensOf = ncNodeParams_L . lensOf @tag

instance HasPrimaryKey NodeContext where
    primaryKey = ncNodeParams_L . primaryKey

instance HasMisbehaviorMetrics NodeContext where
    misbehaviorMetrics = lens getter (flip setter)
      where
        getter nc = nc ^. ncMisbehaviorMetrics_L
        setter mm = set ncMisbehaviorMetrics_L mm

instance HasLens (NetworkConfig KademliaParams) NodeContext (NetworkConfig KademliaParams) where
    lensOf = ncNetworkConfig_L
