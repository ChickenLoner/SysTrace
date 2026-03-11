use std::collections::HashMap;
use crate::types::{ProcessGuid, Timestamp, MitreTechnique};

/// All 29 Sysmon event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SysmonEventType {
    ProcessCreate,           // 1
    FileCreateTime,          // 2
    NetworkConnect,          // 3
    SysmonServiceState,      // 4
    ProcessTerminate,        // 5
    DriverLoad,              // 6
    ImageLoad,               // 7
    CreateRemoteThread,      // 8
    RawAccessRead,           // 9
    ProcessAccess,           // 10
    FileCreate,              // 11
    RegistryCreateDelete,    // 12
    RegistryValueSet,        // 13
    RegistryRename,          // 14
    FileCreateStreamHash,    // 15
    SysmonConfigChange,      // 16
    PipeCreated,             // 17
    PipeConnected,           // 18
    WmiFilter,               // 19
    WmiConsumer,             // 20
    WmiBinding,              // 21
    DnsQuery,                // 22
    FileDelete,              // 23
    ClipboardChange,         // 24
    ProcessTampering,        // 25
    FileDeleteDetected,      // 26
    FileBlockExecutable,     // 27
    FileBlockShredding,      // 28
    FileExecutableDetected,  // 29
    Unknown(u16),
}

impl SysmonEventType {
    pub fn from_event_id(id: u16) -> Self {
        match id {
            1  => Self::ProcessCreate,
            2  => Self::FileCreateTime,
            3  => Self::NetworkConnect,
            4  => Self::SysmonServiceState,
            5  => Self::ProcessTerminate,
            6  => Self::DriverLoad,
            7  => Self::ImageLoad,
            8  => Self::CreateRemoteThread,
            9  => Self::RawAccessRead,
            10 => Self::ProcessAccess,
            11 => Self::FileCreate,
            12 => Self::RegistryCreateDelete,
            13 => Self::RegistryValueSet,
            14 => Self::RegistryRename,
            15 => Self::FileCreateStreamHash,
            16 => Self::SysmonConfigChange,
            17 => Self::PipeCreated,
            18 => Self::PipeConnected,
            19 => Self::WmiFilter,
            20 => Self::WmiConsumer,
            21 => Self::WmiBinding,
            22 => Self::DnsQuery,
            23 => Self::FileDelete,
            24 => Self::ClipboardChange,
            25 => Self::ProcessTampering,
            26 => Self::FileDeleteDetected,
            27 => Self::FileBlockExecutable,
            28 => Self::FileBlockShredding,
            29 => Self::FileExecutableDetected,
            n  => Self::Unknown(n),
        }
    }

    pub fn event_id(&self) -> u16 {
        match self {
            Self::ProcessCreate           => 1,
            Self::FileCreateTime          => 2,
            Self::NetworkConnect          => 3,
            Self::SysmonServiceState      => 4,
            Self::ProcessTerminate        => 5,
            Self::DriverLoad              => 6,
            Self::ImageLoad               => 7,
            Self::CreateRemoteThread      => 8,
            Self::RawAccessRead           => 9,
            Self::ProcessAccess           => 10,
            Self::FileCreate              => 11,
            Self::RegistryCreateDelete    => 12,
            Self::RegistryValueSet        => 13,
            Self::RegistryRename          => 14,
            Self::FileCreateStreamHash    => 15,
            Self::SysmonConfigChange      => 16,
            Self::PipeCreated             => 17,
            Self::PipeConnected           => 18,
            Self::WmiFilter               => 19,
            Self::WmiConsumer             => 20,
            Self::WmiBinding              => 21,
            Self::DnsQuery                => 22,
            Self::FileDelete              => 23,
            Self::ClipboardChange         => 24,
            Self::ProcessTampering        => 25,
            Self::FileDeleteDetected      => 26,
            Self::FileBlockExecutable     => 27,
            Self::FileBlockShredding      => 28,
            Self::FileExecutableDetected  => 29,
            Self::Unknown(n)              => *n,
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::ProcessCreate           => "ProcessCreate",
            Self::FileCreateTime          => "FileCreateTime",
            Self::NetworkConnect          => "NetworkConnect",
            Self::SysmonServiceState      => "SysmonServiceState",
            Self::ProcessTerminate        => "ProcessTerminate",
            Self::DriverLoad              => "DriverLoad",
            Self::ImageLoad               => "ImageLoad",
            Self::CreateRemoteThread      => "CreateRemoteThread",
            Self::RawAccessRead           => "RawAccessRead",
            Self::ProcessAccess           => "ProcessAccess",
            Self::FileCreate              => "FileCreate",
            Self::RegistryCreateDelete    => "RegistryCreateDelete",
            Self::RegistryValueSet        => "RegistryValueSet",
            Self::RegistryRename          => "RegistryRename",
            Self::FileCreateStreamHash    => "FileCreateStreamHash",
            Self::SysmonConfigChange      => "SysmonConfigChange",
            Self::PipeCreated             => "PipeCreated",
            Self::PipeConnected           => "PipeConnected",
            Self::WmiFilter               => "WmiFilter",
            Self::WmiConsumer             => "WmiConsumer",
            Self::WmiBinding              => "WmiBinding",
            Self::DnsQuery                => "DnsQuery",
            Self::FileDelete              => "FileDelete",
            Self::ClipboardChange         => "ClipboardChange",
            Self::ProcessTampering        => "ProcessTampering",
            Self::FileDeleteDetected      => "FileDeleteDetected",
            Self::FileBlockExecutable     => "FileBlockExecutable",
            Self::FileBlockShredding      => "FileBlockShredding",
            Self::FileExecutableDetected  => "FileExecutableDetected",
            Self::Unknown(_)              => "Unknown",
        }
    }
}

/// Type-specific event detail payload.
#[derive(Debug, Clone)]
pub enum EventDetail {
    ProcessCreate {
        command_line: Option<String>,
        current_directory: Option<String>,
        hashes: Option<String>,
        parent_process_guid: Option<ProcessGuid>,
        parent_process_id: Option<u32>,
        parent_image: Option<String>,
        parent_command_line: Option<String>,
        parent_user: Option<String>,
        logon_guid: Option<String>,
        logon_id: Option<String>,
        terminal_session_id: Option<u32>,
        integrity_level: Option<String>,
        file_version: Option<String>,
        description: Option<String>,
        product: Option<String>,
        company: Option<String>,
        original_file_name: Option<String>,
    },
    NetworkConnect {
        protocol: Option<String>,
        initiated: Option<bool>,
        source_ip: Option<String>,
        source_port: Option<u16>,
        source_hostname: Option<String>,
        destination_ip: Option<String>,
        destination_port: Option<u16>,
        destination_hostname: Option<String>,
    },
    FileCreate {
        target_filename: Option<String>,
        creation_utc_time: Option<String>,
    },
    RegistryEvent {
        /// SetValue, CreateKey, DeleteKey, RenameKey
        event_type: Option<String>,
        target_object: Option<String>,
        details: Option<String>,
        new_name: Option<String>,
    },
    DnsQuery {
        query_name: Option<String>,
        query_status: Option<String>,
        query_results: Option<String>,
    },
    PipeEvent {
        /// CreatePipe or ConnectPipe
        event_type: String,
        pipe_name: Option<String>,
    },
    ProcessTerminate,
    CreateRemoteThread {
        source_process_guid: Option<ProcessGuid>,
        source_process_id: Option<u32>,
        source_image: Option<String>,
        target_process_guid: Option<ProcessGuid>,
        target_process_id: Option<u32>,
        target_image: Option<String>,
        start_address: Option<String>,
        start_module: Option<String>,
        start_function: Option<String>,
    },
    ProcessAccess {
        source_process_guid: Option<ProcessGuid>,
        source_process_id: Option<u32>,
        source_image: Option<String>,
        target_process_guid: Option<ProcessGuid>,
        target_process_id: Option<u32>,
        target_image: Option<String>,
        granted_access: Option<String>,
        call_trace: Option<String>,
    },
    FileDeleteEvent {
        target_filename: Option<String>,
        hashes: Option<String>,
        is_executable: Option<bool>,
    },
    DriverLoad {
        image_loaded: Option<String>,
        hashes: Option<String>,
        signature: Option<String>,
        signature_status: Option<String>,
    },
    ImageLoad {
        image_loaded: Option<String>,
        hashes: Option<String>,
        signature: Option<String>,
        signature_status: Option<String>,
        signed: Option<bool>,
    },
    FileCreateStreamHash {
        target_filename: Option<String>,
        hash: Option<String>,
        contents: Option<String>,
    },
    ProcessTampering {
        tampering_type: Option<String>,
    },
    ClipboardChange {
        session: Option<String>,
        client_info: Option<String>,
        hashes: Option<String>,
    },
    RawAccessRead {
        device: Option<String>,
    },
    SysmonConfigChange {
        configuration: Option<String>,
        configuration_file_hash: Option<String>,
    },
    FileCreateTime {
        target_filename: Option<String>,
        creation_utc_time: Option<String>,
        previous_creation_utc_time: Option<String>,
    },
    WmiActivity {
        event_type: String,
        operation: Option<String>,
        user: Option<String>,
        event_namespace: Option<String>,
        name: Option<String>,
        query: Option<String>,
        destination: Option<String>,
        consumer_type: Option<String>,
        filter_name: Option<String>,
    },
    /// Fallback for unrecognized or exotic event types.
    Generic {
        fields: HashMap<String, String>,
    },
}

/// A fully parsed Sysmon event with common fields + type-specific detail.
///
/// `computer`, `image`, and `user` are stored as interned `lasso::Spur` keys
/// to avoid heap-allocating thousands of duplicate strings.
/// Resolve them through the `SharedRodeo` owned by `AppState`.
#[derive(Debug, Clone)]
pub struct SysmonEvent {
    // --- Common fields ---
    pub event_id: u16,
    pub event_type: SysmonEventType,
    pub time_created: Timestamp,
    pub record_number: u64,
    /// Interned hostname. Resolve via `SharedRodeo::resolve`.
    pub computer: lasso::Spur,
    pub process_guid: Option<ProcessGuid>,
    pub process_id: Option<u32>,
    /// Interned image path (e.g. `C:\Windows\System32\svchost.exe`).
    pub image: Option<lasso::Spur>,
    /// Interned user name.
    pub user: Option<lasso::Spur>,
    pub rule_name: Option<String>,
    pub mitre_technique: Option<MitreTechnique>,

    // --- Type-specific payload ---
    pub detail: EventDetail,
}

impl SysmonEvent {
    /// For cross-process events (EventId 8, 10), returns the secondary (target) ProcessGuid.
    pub fn secondary_process_guid(&self) -> Option<ProcessGuid> {
        match &self.detail {
            EventDetail::CreateRemoteThread { target_process_guid, .. } => *target_process_guid,
            EventDetail::ProcessAccess    { target_process_guid, .. } => *target_process_guid,
            _ => None,
        }
    }
}
