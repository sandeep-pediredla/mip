package com.forcepoint.dlp.mip.java_lib_integration;

import com.microsoft.informationprotection.AssignmentMethod;
import com.microsoft.informationprotection.Label;
import com.microsoft.informationprotection.ProtectionDescriptor;
import com.microsoft.informationprotection.internal.utils.Pair;
import com.microsoft.informationprotection.policy.action.ActionType;
import com.microsoft.informationprotection.policy.ContentFormat;
import com.microsoft.informationprotection.policy.ExecutionState;
import com.microsoft.informationprotection.policy.MetadataEntry;
import com.microsoft.informationprotection.policy.MetadataVersion;
import com.microsoft.informationprotection.policy.MetadataVersionFormat;
import java.util.ArrayList;
import java.util.List;

public class ExecutionStateImpl extends ExecutionState {

  private Label newLabel;

  public ExecutionStateImpl(Label newLabel) {
    this.newLabel = newLabel;
  }

  @Override
  public Label getNewLabel() {
    return newLabel;
  }

  @Override
  public AssignmentMethod getNewLabelAssignmentMethod() {
    return AssignmentMethod.AUTO;
  }

  @Override
  public ProtectionDescriptor getProtectionDescriptor() {
    return new ProtectionDescriptor(new ArrayList<>(), null);
  }

  @Override
  public String getContentFormat() {
    return ContentFormat.File;
  }
  
  @Override
  public MetadataVersion getContentMetadataVersion() {
    return new MetadataVersion(0, MetadataVersionFormat.DEFAULT);
  }

  @Override
  public ActionType getSupportedActions() {
    return ActionType.Custom;
  }

  @Override
  public Pair<Boolean, String> isDowngradeJustified() {
    return new Pair<>(true, "Justification Message");
  }

  @Override
  public String getContentIdentifier() {
    return "FilePathOrMailSubject";
  }

  @Override
  public List<MetadataEntry> getContentMetadata(List<String> names,
      List<String> namePrefixes) {
    return new ArrayList<>();
  }
}
