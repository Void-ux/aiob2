from typing import TypedDict, Optional, List


class Permissions(TypedDict):
    capabilities: List[str]
    bucketId: Optional[str]
    bucketName: Optional[str]
    namePrefix: Optional[str]


class AccountAuthorizationPayload(TypedDict):
    accountId: str
    authorizationToken: str
    allowed: Permissions
    apiUrl: str
    downloadUrl: str
    recommendedPartSize: int
    absoluteMinimumPartSize: int
    s3ApiUrl: str
    capabilities: List[str]
