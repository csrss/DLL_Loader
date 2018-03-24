
#define MODE_FIND_STATUS	112
#define MODE_ADD_STATUS		113
#define MODE_MOD_STATUS		114
#define MODE_DEL_STATUS		115
#define STATUS_CODE			L"STATUS_CODE"
#define STATUS_NAME			L"STATUS_NAME"
#define STATUS_MESSAGE		L"STATUS_MESSAGE"
#define STATUS_FOUND		2
#define STATUS_NOTFOUND		1
#define STATUS_FIND_ONLY	3

int __stdcall ClearVals(HWND hWnd){
	SetDlgItemTextW(hWnd, IDC_EDIT1, L"");
	SetDlgItemTextW(hWnd, IDC_EDIT2, L"");
	SetDlgItemTextW(hWnd, IDC_EDIT3, L"");
	return 0;
}

int __stdcall NewNtStatusTable(HWND hWnd){
sqlite3 *db; 
int rc; 
char *zErr; 
char debug[MAX_PATH];
char *sql = "CREATE TABLE NtStatusTable							\
                          (										\
                          Id INTEGER PRIMARY KEY,				\
                          STATUS_CODE longtext NOT NULL,		\
						  STATUS_NAME longtext NOT NULL,		\
                          STATUS_MESSAGE longtext NOT NULL		\
                          );";

rc = sqlite3_open16(ULTIMA_LOADER_DATABASE_FILE, &db); 
        if(rc) {
			SetDlgItemTextW(hWnd, IDC_EDIT4, L"Cannot open or create DB. Error!");
            sqlite3_close(db); 
            return -1;
        }
rc = sqlite3_exec(db, sql, NULL, NULL, &zErr); 
        if(rc != SQLITE_OK) { 
                if (zErr != NULL) { 
                        sprintf(debug, "SQL error: %s\n", zErr);
						SetDlgItemTextA(hWnd, IDC_EDIT4, debug);
						sqlite3_close(db); 
						sqlite3_free(zErr); 
						return -1;
                } 
		}  else {
			SetDlgItemTextW(hWnd, IDC_EDIT4, L"Table 'NtStatusTable' successfuly created!");
		}
sqlite3_close(db); 
return 0;
}

int __stdcall DropNtStatusTable(HWND hWnd){
sqlite3 *db; 
int rc; 
char *zErr; 
char debug[MAX_PATH];
char *sql = "DROP TABLE NtStatusTable;";
rc = sqlite3_open16(ULTIMA_LOADER_DATABASE_FILE, &db); 
        if(rc) {
			SetDlgItemTextW(hWnd, IDC_EDIT4, L"Cannot open DB. Error!");
            sqlite3_close(db); 
            return -1;
        }
rc = sqlite3_exec(db, sql, NULL, NULL, &zErr); 
        if(rc != SQLITE_OK) { 
                if (zErr != NULL) { 
                        sprintf(debug, "SQL error: %s\n", zErr);
						SetDlgItemTextA(hWnd, IDC_EDIT4, debug);
						sqlite3_close(db); 
						sqlite3_free(zErr); 
						return -1;
                } 
		}  else {
			SetDlgItemTextW(hWnd, IDC_EDIT4, L"Table 'NtStatusTable' successfuly dropped!");
		}
sqlite3_close(db); 
return 0;
}

int __stdcall CheckValueExistance(wchar_t *Row, wchar_t *Val, HWND hWnd, int Mode){
	wchar_t *SqlQuery;
	sqlite3 *db;
	char debug[MAX_PATH];
	sqlite3_stmt *stmt;
	int rc; 
	int Status = 0;
	SqlQuery = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 
						sizeof(wchar_t) * (wcslen(Val)) + MAX_PATH);
	swprintf(SqlQuery, L"SELECT * FROM NtStatusTable WHERE %s = '%s'", Row, Val);
	rc = sqlite3_open16(ULTIMA_LOADER_DATABASE_FILE, &db); 
        if(rc) {
			SetDlgItemTextW(hWnd, IDC_EDIT4, L"Cannot open DB. Error!");
            sqlite3_close(db); 
            return -1;
        }
	rc = sqlite3_prepare16(db, SqlQuery, -1, &stmt, 0);
        if(rc != SQLITE_OK) { 
			sprintf(debug, "sqlite3_prepare16 failed! Status: %s", sqlite3_errmsg(db));
			SetDlgItemTextA(hWnd, IDC_EDIT4, debug);
			sqlite3_close(db); 
			return -1;
		}  else {
			SetDlgItemTextW(hWnd, IDC_EDIT4, L"Query prepared, initializing step...");
		}
	rc = sqlite3_step(stmt);
	switch(rc){
		case SQLITE_DONE:
			Status = STATUS_NOTFOUND;
			break;
		case SQLITE_ROW:
			if(Mode == STATUS_FIND_ONLY){
				SetDlgItemTextW(hWnd, IDC_EDIT1, (LPCWSTR)sqlite3_column_text16(stmt,1));
				SetDlgItemTextW(hWnd, IDC_EDIT2, (LPCWSTR)sqlite3_column_text16(stmt,2));
				SetDlgItemTextW(hWnd, IDC_EDIT3, (LPCWSTR)sqlite3_column_text16(stmt,3));
				Status = STATUS_FOUND;
			} else {
				Status = STATUS_FOUND;
			}
			break;
		default:
			sprintf(debug, "sqlite3_step failed! Status: %s", sqlite3_errmsg(db));
			SetDlgItemTextA(hWnd, IDC_EDIT4, debug);
			return -1;
			break;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db); 
	SetDlgItemTextW(hWnd, IDC_EDIT4, L"DONE.");
	return Status;
}

int __stdcall NtStatusInsertStatus(wchar_t *Code, wchar_t *Name, wchar_t *Msg, HWND hWnd){
	wchar_t *SqlQuery;
	sqlite3 *db;
	char debug[MAX_PATH];
	sqlite3_stmt *stmt;
	int rc, Status; 
	if(Code == NULL || wcscmp(Code, L"") == 0 || Name == NULL || wcscmp(Name, L"") == 0){
		SetDlgItemTextW(hWnd, IDC_EDIT4, L"Status code or name not specified!");
		return -1;
	}
	SqlQuery = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 
									sizeof(wchar_t) * (wcslen(Code)+wcslen(Name)+wcslen(Msg))+1000);
	swprintf(SqlQuery, L"INSERT INTO NtStatusTable (Id, STATUS_CODE, STATUS_NAME, STATUS_MESSAGE) VALUES (NULL, '%s', '%s', '%s')", 
							Code, Name, Msg);
	Status = CheckValueExistance(STATUS_CODE, Code, hWnd, 9);
	if(Status == STATUS_NOTFOUND){
		Status = CheckValueExistance(STATUS_NAME, Name, hWnd, 9);
		if(Status == STATUS_NOTFOUND){
			Status = CheckValueExistance(STATUS_MESSAGE, Msg, hWnd, 9);
			if(Status == STATUS_NOTFOUND){
				SetDlgItemTextW(hWnd, IDC_EDIT4, L"");
			} else {
				SetDlgItemTextW(hWnd, IDC_EDIT4, L"Status already in database! Use 'Edit' to modify status information");
				return -1;
			}
		} else {
			SetDlgItemTextW(hWnd, IDC_EDIT4, L"Status already in database! Use 'Edit' to modify status information");
			return -1;
		}
	} else {
		SetDlgItemTextW(hWnd, IDC_EDIT4, L"Status already in database! Use 'Edit' to modify status information");
		return -1;
	}

	rc = sqlite3_open16(ULTIMA_LOADER_DATABASE_FILE, &db); 
        if(rc) {
			SetDlgItemTextW(hWnd, IDC_EDIT4, L"Cannot open DB. Error!");
            sqlite3_close(db); 
            return -1;
        }
	rc = sqlite3_prepare16(db, SqlQuery, -1, &stmt, 0);
        if(rc != SQLITE_OK) { 
			sprintf(debug, "sqlite3_prepare16 failed! Status: %s", sqlite3_errmsg(db));
			SetDlgItemTextA(hWnd, IDC_EDIT4, debug);
			sqlite3_close(db); 
			return -1;
		}  else {
			SetDlgItemTextW(hWnd, IDC_EDIT4, L"Query prepared, initializing step...");
		}
	rc = sqlite3_step(stmt);
	if( rc != SQLITE_DONE ){
		sprintf(debug, "sqlite3_step failed! Status: %s", sqlite3_errmsg(db));
		SetDlgItemTextA(hWnd, IDC_EDIT4, debug);
		return -1;
	} else {
		SetDlgItemTextW(hWnd, IDC_EDIT4, L"SQL sqlite3_step OK!");
	}
	sqlite3_finalize(stmt);
	SetDlgItemTextW(hWnd, IDC_EDIT4, L"New NTSTATUS added to database!");
	sqlite3_close(db); 
	return 0;
}

int __stdcall NtStatusDeleteRow(wchar_t *Row, wchar_t *Val, HWND hWnd){
	wchar_t *SqlQuery;
	sqlite3 *db;
	char debug[MAX_PATH];
	sqlite3_stmt *stmt;
	int rc; 
	if(Val == NULL || wcscmp(Val, L"") == 0){
		SetDlgItemTextW(hWnd, IDC_EDIT4, L"Status code not specified!");
		return -1;
	}
	if(CheckValueExistance(STATUS_CODE, Val, hWnd, 9) == STATUS_NOTFOUND){
		SetDlgItemTextW(hWnd, IDC_EDIT4, L"Such status not found.");
		return -1;
	}
		SqlQuery = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 
						sizeof(wchar_t) * (wcslen(Val)) + MAX_PATH);
		swprintf(SqlQuery, L"DELETE FROM NtStatusTable WHERE %s = '%s'", Row, Val);
		rc = sqlite3_open16(ULTIMA_LOADER_DATABASE_FILE, &db); 
        if(rc) {
			SetDlgItemTextW(hWnd, IDC_EDIT4, L"Cannot open DB. Error!");
            sqlite3_close(db); 
            return -1;
        }
		rc = sqlite3_prepare16(db, SqlQuery, -1, &stmt, 0);
        if(rc != SQLITE_OK) { 
			sprintf(debug, "sqlite3_prepare16 failed! Status: %s", sqlite3_errmsg(db));
			SetDlgItemTextA(hWnd, IDC_EDIT4, debug);
			sqlite3_close(db); 
			return -1;
		}  else {
			SetDlgItemTextW(hWnd, IDC_EDIT4, L"Query prepared, initializing step...");
		}
	rc = sqlite3_step(stmt);
	if( rc != SQLITE_DONE ){
		sprintf(debug, "sqlite3_step failed! Status: %s", sqlite3_errmsg(db));
		SetDlgItemTextA(hWnd, IDC_EDIT4, debug);
		return -1;
	} else {
		SetDlgItemTextW(hWnd, IDC_EDIT4, L"SQL sqlite3_step OK!");
	}
	sqlite3_finalize(stmt);
	SetDlgItemTextW(hWnd, IDC_EDIT4, L"Status deleted.");
	sqlite3_close(db); 
	return 0;
}

int __stdcall NtStatusModifyStatus(wchar_t *Code, wchar_t *Name, wchar_t *Msg, HWND hWnd){
	wchar_t *SqlQuery;
	sqlite3 *db;
	char debug[MAX_PATH];
	sqlite3_stmt *stmt;
	int rc; 
	if(Code == NULL || wcscmp(Code, L"") == 0){
		SetDlgItemTextW(hWnd, IDC_EDIT4, L"Status code not specified!");
		return -1;
	}
	if(CheckValueExistance(STATUS_CODE, Code, hWnd, 9) == STATUS_NOTFOUND){
		SetDlgItemTextW(hWnd, IDC_EDIT4, L"Such status not found.");
		return -1;
	}
	SqlQuery = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 
									sizeof(wchar_t) * (wcslen(Code)+wcslen(Name)+wcslen(Msg))+1000);
	swprintf(SqlQuery, L"UPDATE NtStatusTable SET STATUS_NAME = '%s', STATUS_MESSAGE = '%s' WHERE STATUS_CODE = '%s'", 
							Name, Msg, Code);
	rc = sqlite3_open16(ULTIMA_LOADER_DATABASE_FILE, &db); 
        if(rc) {
			SetDlgItemTextW(hWnd, IDC_EDIT4, L"Cannot open DB. Error!");
            sqlite3_close(db); 
            return -1;
        }
	rc = sqlite3_prepare16(db, SqlQuery, -1, &stmt, 0);
        if(rc != SQLITE_OK) { 
			sprintf(debug, "sqlite3_prepare16 failed! Status: %s", sqlite3_errmsg(db));
			SetDlgItemTextA(hWnd, IDC_EDIT4, debug);
			sqlite3_close(db); 
			return -1;
		}  else {
			SetDlgItemTextW(hWnd, IDC_EDIT4, L"Query prepared, initializing step...");
		}
	rc = sqlite3_step(stmt);
	if( rc != SQLITE_DONE ){
		sprintf(debug, "sqlite3_step failed! Status: %s", sqlite3_errmsg(db));
		SetDlgItemTextA(hWnd, IDC_EDIT4, debug);
		return -1;
	} else {
		SetDlgItemTextW(hWnd, IDC_EDIT4, L"SQL sqlite3_step OK!");
	}
	sqlite3_finalize(stmt);
	SetDlgItemTextW(hWnd, IDC_EDIT4, L"Status updated.");
	sqlite3_close(db); 
	return 0;
}

int __stdcall ProcessNtStatusRequest(wchar_t *Code, wchar_t *Name, wchar_t *Msg, int mode, HWND hWnd){
	int Status;
	switch (mode){
		case MODE_FIND_STATUS:
			Status = CheckValueExistance(STATUS_CODE, Code, hWnd, STATUS_FIND_ONLY);
			if(Status == STATUS_NOTFOUND){
				ClearVals(hWnd);
				SetDlgItemTextW(hWnd, IDC_EDIT4, L"Not found.");
			}
		break;

		case MODE_ADD_STATUS:
			NtStatusInsertStatus(Code, Name, Msg, hWnd);
			ClearVals(hWnd);
		break;

		case MODE_MOD_STATUS:
			NtStatusModifyStatus(Code, Name, Msg, hWnd);
		break;

		case MODE_DEL_STATUS:
			NtStatusDeleteRow(STATUS_CODE, Code, hWnd);
			ClearVals(hWnd);
		break;
	}

	return 1;
}

static BOOL NtStatusDialogProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	wchar_t Code[MAX_PATH] = {0};
	wchar_t Name[1024] = {0};
	wchar_t Msg[10240] = {0};
	unsigned int BytesReturned = 0;
switch(uMsg)
   {
       case WM_INITDIALOG:
           return TRUE;
       case WM_DESTROY:
           EndDialog(hWnd, 0);
           return TRUE;
	   case WM_COMMAND:
			switch (LOWORD(wParam)) {
				case IDOK:	// find status
					{
						BytesReturned = GetDlgItemText(hWnd, IDC_EDIT1, Code, sizeof Code);
						BytesReturned = GetDlgItemText(hWnd, IDC_EDIT2, Name, sizeof Name);
						BytesReturned = GetDlgItemText(hWnd, IDC_EDIT3, Msg, sizeof Msg);
						ProcessNtStatusRequest(Code, Name, Msg, MODE_FIND_STATUS, hWnd);
					}
					break;
				case IDCANCEL:	// close dialog
					EndDialog(hWnd, 0);
					break;
				case IDC_BUTTON1:	// add status to database
						BytesReturned = GetDlgItemText(hWnd, IDC_EDIT1, Code, sizeof Code);
						BytesReturned = GetDlgItemText(hWnd, IDC_EDIT2, Name, sizeof Name);
						BytesReturned = GetDlgItemText(hWnd, IDC_EDIT3, Msg, sizeof Msg);
						ProcessNtStatusRequest(Code, Name, Msg, MODE_ADD_STATUS, hWnd);
					break;
				case IDC_BUTTON2:	// adit current status
						BytesReturned = GetDlgItemText(hWnd, IDC_EDIT1, Code, sizeof Code);
						BytesReturned = GetDlgItemText(hWnd, IDC_EDIT2, Name, sizeof Name);
						BytesReturned = GetDlgItemText(hWnd, IDC_EDIT3, Msg, sizeof Msg);
						ProcessNtStatusRequest(Code, Name, Msg, MODE_MOD_STATUS, hWnd);
					break;
				case IDC_BUTTON3:	// delete current status
						BytesReturned = GetDlgItemText(hWnd, IDC_EDIT1, Code, sizeof Code);
						BytesReturned = GetDlgItemText(hWnd, IDC_EDIT2, Name, sizeof Name);
						BytesReturned = GetDlgItemText(hWnd, IDC_EDIT3, Msg, sizeof Msg);
						ProcessNtStatusRequest(Code, Name, Msg, MODE_DEL_STATUS, hWnd);
					break;
				case IDC_BUTTON4:
					NewNtStatusTable(hWnd);
					break;
				case IDC_BUTTON5:
					DropNtStatusTable(hWnd);
					break;
			}
		   return TRUE;
   }
   return FALSE;
}
