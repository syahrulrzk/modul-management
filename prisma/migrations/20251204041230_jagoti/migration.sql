-- CreateTable
CREATE TABLE "UploadHistory" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "moduleName" TEXT NOT NULL,
    "fileName" TEXT NOT NULL,
    "fileSize" INTEGER,
    "uploadTimestamp" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "uploader" TEXT
);
