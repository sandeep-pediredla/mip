package com.forcepoint.dlp.mip.java_lib_integration;

import com.microsoft.informationprotection.DataState;
import com.microsoft.informationprotection.file.FileExecutionState;

public class FileExecutionStateImpl extends FileExecutionState {

  private DataState dataState;

  public FileExecutionStateImpl(DataState dataState) {
    this.dataState = dataState;
  }

  @Override
  public DataState getDataState() {
    return dataState;
  }
}
