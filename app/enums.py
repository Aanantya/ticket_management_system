from enum import Enum

# Enums for Role and Ticket Status
class RoleEnum(Enum):
    ADMIN = 'Admin'
    SUBADMIN = 'Subadmin'
    AGENT = 'Agent'
    USER = 'User'

class TicketStatusEnum(Enum):
    NONE = '-- select --'
    PENDING = 'Pending'
    APPROVED = 'Approved'
    READY_TO_DISPATCH = 'Ready to Dispatch'
    DISPATCHED = 'Dispatched'
    CLOSED = 'Closed'

class TicketPriorityEnum(Enum):
    NONE = '-- select --'
    LOW = 'Low'
    MEDIUM = 'Medium'
    HIGH = 'High'
    EMERGENCY = 'Emergency'