// Centralized icon set backed by lucide-react. Every export keeps the same
// name/shape (`{ size?: number }`) as the original hand-drawn SVG set so call
// sites across the app don't need to change when icons are swapped.
import {
  Activity, AlertTriangle, ArrowUpRight, BarChart3, Boxes, Check, CheckCircle2,
  ChevronDown, ChevronRight, Clock, Cloud, Container, Database, Download,
  FileCode2, FileText, GitBranch, GitCompareArrows, Home, Layers, LayoutGrid,
  LogOut, Menu, Moon, Network, Play, Plug, Plus, RefreshCw, Search, Server, Settings,
  Shield, ShieldAlert, Sun, Trash2, Upload, X, XCircle,
} from 'lucide-react';

type P = { size?: number };

export const IconHome = ({ size = 16 }: P) => <Home size={size} />;
export const IconRules = ({ size = 16 }: P) => <Layers size={size} />;
export const IconGraph = ({ size = 16 }: P) => <GitBranch size={size} />;
export const IconCompare = ({ size = 16 }: P) => <GitCompareArrows size={size} />;
export const IconSettings = ({ size = 16 }: P) => <Settings size={size} />;
export const IconSearch = ({ size = 16 }: P) => <Search size={size} />;
export const IconSun = ({ size = 16 }: P) => <Sun size={size} />;
export const IconMoon = ({ size = 16 }: P) => <Moon size={size} />;
export const IconMenu = ({ size = 16 }: P) => <Menu size={size} />;
export const IconLogOut = ({ size = 16 }: P) => <LogOut size={size} />;
export const IconX = ({ size = 16 }: P) => <X size={size} />;
export const IconDownload = ({ size = 16 }: P) => <Download size={size} />;
export const IconCollect = ({ size = 16 }: P) => <Plug size={size} />;
export const IconDecode = ({ size = 16 }: P) => <FileCode2 size={size} />;
export const IconEnrich = ({ size = 16 }: P) => <Layers size={size} />;
export const IconAlert = ({ size = 16 }: P) => <AlertTriangle size={size} />;
export const IconImprove = ({ size = 16 }: P) => <RefreshCw size={size} />;
export const IconShield = ({ size = 16 }: P) => <Shield size={size} />;
export const IconServer = ({ size = 16 }: P) => <Server size={size} />;
export const IconFile = ({ size = 16 }: P) => <FileText size={size} />;
export const IconPlus = ({ size = 16 }: P) => <Plus size={size} />;
export const IconTrash = ({ size = 16 }: P) => <Trash2 size={size} />;
export const IconRefresh = ({ size = 16 }: P) => <RefreshCw size={size} />;

// ---- dashboard-specific additions ----
export const IconShieldAlert = ({ size = 16 }: P) => <ShieldAlert size={size} />;
export const IconCheckCircle = ({ size = 16 }: P) => <CheckCircle2 size={size} />;
export const IconXCircle = ({ size = 16 }: P) => <XCircle size={size} />;
export const IconAlertTriangle = ({ size = 16 }: P) => <AlertTriangle size={size} />;
export const IconGitBranch = ({ size = 16 }: P) => <GitBranch size={size} />;
export const IconLayers = ({ size = 16 }: P) => <Layers size={size} />;
export const IconDatabase = ({ size = 16 }: P) => <Database size={size} />;
export const IconUpload = ({ size = 16 }: P) => <Upload size={size} />;
export const IconGitCompare = ({ size = 16 }: P) => <GitCompareArrows size={size} />;
export const IconFileText = ({ size = 16 }: P) => <FileText size={size} />;
export const IconActivity = ({ size = 16 }: P) => <Activity size={size} />;
export const IconTrendingUp = ({ size = 16 }: P) => <BarChart3 size={size} />;
export const IconBoxes = ({ size = 16 }: P) => <Boxes size={size} />;
export const IconNetwork = ({ size = 16 }: P) => <Network size={size} />;
export const IconClock = ({ size = 16 }: P) => <Clock size={size} />;
export const IconArrowUpRight = ({ size = 16 }: P) => <ArrowUpRight size={size} />;
export const IconCloud = ({ size = 16 }: P) => <Cloud size={size} />;
export const IconContainer = ({ size = 16 }: P) => <Container size={size} />;
export const IconLayoutGrid = ({ size = 16 }: P) => <LayoutGrid size={size} />;
export const IconChevronDown = ({ size = 16 }: P) => <ChevronDown size={size} />;
export const IconChevronRight = ({ size = 16 }: P) => <ChevronRight size={size} />;
export const IconPlay = ({ size = 16 }: P) => <Play size={size} />;
export const IconCheck = ({ size = 16 }: P) => <Check size={size} />;
