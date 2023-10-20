/**
 * @name freerdp-8241ab42fdf0cc89cf69fc574bf6360c9977a0d4-ntlm_read_AuthenticateMessage
 * @id cpp/freerdp/8241ab42fdf0cc89cf69fc574bf6360c9977a0d4/ntlm-read-AuthenticateMessage
 * @description freerdp-8241ab42fdf0cc89cf69fc574bf6360c9977a0d4-winpr/libwinpr/sspi/NTLM/ntlm_message.c-ntlm_read_AuthenticateMessage CVE-2020-11087
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(Initializer target_1 |
		target_1.getExpr() instanceof Literal
		and target_1.getExpr().getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Initializer target_2 |
		target_2.getExpr() instanceof Literal
		and target_2.getExpr().getEnclosingFunction() = func)
}

predicate func_3(RelationalOperation target_135, Function func) {
	exists(GotoStmt target_3 |
		target_3.toString() = "goto ..."
		and target_3.getName() ="fail"
		and target_3.getParent().(IfStmt).getCondition()=target_135
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(EqualityOperation target_136, Function func) {
	exists(GotoStmt target_4 |
		target_4.toString() = "goto ..."
		and target_4.getName() ="fail"
		and target_4.getParent().(IfStmt).getCondition()=target_136
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(RelationalOperation target_137, Function func) {
	exists(GotoStmt target_5 |
		target_5.toString() = "goto ..."
		and target_5.getName() ="fail"
		and target_5.getParent().(IfStmt).getCondition()=target_137
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(RelationalOperation target_138, Function func) {
	exists(GotoStmt target_6 |
		target_6.toString() = "goto ..."
		and target_6.getName() ="fail"
		and target_6.getParent().(IfStmt).getCondition()=target_138
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(RelationalOperation target_139, Function func) {
	exists(GotoStmt target_7 |
		target_7.toString() = "goto ..."
		and target_7.getName() ="fail"
		and target_7.getParent().(IfStmt).getCondition()=target_139
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(RelationalOperation target_140, Function func) {
	exists(GotoStmt target_8 |
		target_8.toString() = "goto ..."
		and target_8.getName() ="fail"
		and target_8.getParent().(IfStmt).getCondition()=target_140
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(RelationalOperation target_141, Function func) {
	exists(GotoStmt target_9 |
		target_9.toString() = "goto ..."
		and target_9.getName() ="fail"
		and target_9.getParent().(IfStmt).getCondition()=target_141
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(RelationalOperation target_142, Function func) {
	exists(GotoStmt target_10 |
		target_10.toString() = "goto ..."
		and target_10.getName() ="fail"
		and target_10.getParent().(IfStmt).getCondition()=target_142
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Variable vs_684, ExprStmt target_38, RelationalOperation target_137) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("Stream_GetRemainingLength")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_38.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getArgument(0).(VariableAccess).getLocation())
		and target_11.getArgument(0).(VariableAccess).getLocation().isBefore(target_137.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_13(LogicalOrExpr target_39, Function func) {
	exists(GotoStmt target_13 |
		target_13.toString() = "goto ..."
		and target_13.getName() ="fail"
		and target_13.getParent().(IfStmt).getCondition()=target_39
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(BitwiseAndExpr target_40, Function func) {
	exists(GotoStmt target_14 |
		target_14.toString() = "goto ..."
		and target_14.getName() ="fail"
		and target_14.getParent().(IfStmt).getCondition()=target_40
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(RelationalOperation target_143, Function func) {
	exists(GotoStmt target_15 |
		target_15.toString() = "goto ..."
		and target_15.getName() ="fail"
		and target_15.getParent().(IfStmt).getCondition()=target_143
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Function func) {
	exists(AssignExpr target_16 |
		target_16.getLValue().(VariableAccess).getType().hasName("SECURITY_STATUS")
		and target_16.getRValue() instanceof Literal
		and target_16.getEnclosingFunction() = func)
}

predicate func_17(RelationalOperation target_42, Function func) {
	exists(GotoStmt target_17 |
		target_17.toString() = "goto ..."
		and target_17.getName() ="fail"
		and target_17.getParent().(IfStmt).getCondition()=target_42
		and target_17.getEnclosingFunction() = func)
}

predicate func_18(RelationalOperation target_43, Function func) {
	exists(GotoStmt target_18 |
		target_18.toString() = "goto ..."
		and target_18.getName() ="fail"
		and target_18.getParent().(IfStmt).getCondition()=target_43
		and target_18.getEnclosingFunction() = func)
}

predicate func_19(RelationalOperation target_44, Function func) {
	exists(GotoStmt target_19 |
		target_19.toString() = "goto ..."
		and target_19.getName() ="fail"
		and target_19.getParent().(IfStmt).getCondition()=target_44
		and target_19.getEnclosingFunction() = func)
}

predicate func_20(RelationalOperation target_45, Function func) {
	exists(GotoStmt target_20 |
		target_20.toString() = "goto ..."
		and target_20.getName() ="fail"
		and target_20.getParent().(IfStmt).getCondition()=target_45
		and target_20.getEnclosingFunction() = func)
}

predicate func_21(RelationalOperation target_46, Function func) {
	exists(GotoStmt target_21 |
		target_21.toString() = "goto ..."
		and target_21.getName() ="fail"
		and target_21.getParent().(IfStmt).getCondition()=target_46
		and target_21.getEnclosingFunction() = func)
}

predicate func_22(RelationalOperation target_144, Function func) {
	exists(GotoStmt target_22 |
		target_22.toString() = "goto ..."
		and target_22.getName() ="fail"
		and target_22.getParent().(IfStmt).getCondition()=target_144
		and target_22.getEnclosingFunction() = func)
}

predicate func_23(Function func) {
	exists(AssignExpr target_23 |
		target_23.getLValue().(VariableAccess).getType().hasName("SECURITY_STATUS")
		and target_23.getRValue() instanceof Literal
		and target_23.getEnclosingFunction() = func)
}

predicate func_24(Function func) {
	exists(AssignExpr target_24 |
		target_24.getLValue().(VariableAccess).getType().hasName("int")
		and target_24.getRValue() instanceof FunctionCall
		and target_24.getEnclosingFunction() = func)
}

predicate func_25(BlockStmt target_145, Function func) {
	exists(RelationalOperation target_25 |
		 (target_25 instanceof GTExpr or target_25 instanceof LTExpr)
		and target_25.getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_25.getGreaterOperand() instanceof Literal
		and target_25.getParent().(IfStmt).getThen()=target_145
		and target_25.getEnclosingFunction() = func)
}

predicate func_26(RelationalOperation target_60, Function func) {
	exists(GotoStmt target_26 |
		target_26.toString() = "goto ..."
		and target_26.getName() ="fail"
		and target_26.getParent().(IfStmt).getCondition()=target_60
		and target_26.getEnclosingFunction() = func)
}

predicate func_27(Function func) {
	exists(AssignExpr target_27 |
		target_27.getLValue().(VariableAccess).getType().hasName("SECURITY_STATUS")
		and target_27.getRValue() instanceof Literal
		and target_27.getEnclosingFunction() = func)
}

predicate func_28(RelationalOperation target_146, Function func) {
	exists(GotoStmt target_28 |
		target_28.toString() = "goto ..."
		and target_28.getName() ="fail"
		and target_28.getParent().(IfStmt).getCondition()=target_146
		and target_28.getEnclosingFunction() = func)
}

predicate func_29(NotExpr target_63, Function func) {
	exists(GotoStmt target_29 |
		target_29.toString() = "goto ..."
		and target_29.getName() ="fail"
		and target_29.getParent().(IfStmt).getCondition()=target_63
		and target_29.getEnclosingFunction() = func)
}

predicate func_30(BitwiseAndExpr target_64, Function func) {
	exists(GotoStmt target_30 |
		target_30.toString() = "goto ..."
		and target_30.getName() ="fail"
		and target_30.getParent().(IfStmt).getCondition()=target_64
		and target_30.getEnclosingFunction() = func)
}

predicate func_31(Function func) {
	exists(AssignExpr target_31 |
		target_31.getLValue().(VariableAccess).getType().hasName("SECURITY_STATUS")
		and target_31.getRValue() instanceof Literal
		and target_31.getEnclosingFunction() = func)
}

predicate func_32(NotExpr target_69, Function func) {
	exists(GotoStmt target_32 |
		target_32.toString() = "goto ..."
		and target_32.getName() ="fail"
		and target_32.getParent().(IfStmt).getCondition()=target_69
		and target_32.getEnclosingFunction() = func)
}

predicate func_33(Function func) {
	exists(AssignExpr target_33 |
		target_33.getLValue().(VariableAccess).getType().hasName("SECURITY_STATUS")
		and target_33.getRValue() instanceof Literal
		and target_33.getEnclosingFunction() = func)
}

predicate func_34(RelationalOperation target_72, Function func) {
	exists(GotoStmt target_34 |
		target_34.toString() = "goto ..."
		and target_34.getName() ="fail"
		and target_34.getParent().(IfStmt).getCondition()=target_72
		and target_34.getEnclosingFunction() = func)
}

predicate func_35(RelationalOperation target_140, Function func) {
	exists(IfStmt target_35 |
		target_35.getCondition() instanceof NotExpr
		and target_35.getThen().(GotoStmt).toString() = "goto ..."
		and target_35.getThen().(GotoStmt).getName() ="fail"
		and target_35.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_35
		and target_35.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_140
		and target_35.getEnclosingFunction() = func)
}

predicate func_36(Function func) {
	exists(LabelStmt target_36 |
		target_36.toString() = "label ...:"
		and target_36.getName() ="fail"
		and (func.getEntryPoint().(BlockStmt).getStmt(47)=target_36 or func.getEntryPoint().(BlockStmt).getStmt(47).getFollowingStmt()=target_36))
}

predicate func_38(Variable vs_684, RelationalOperation target_135, ExprStmt target_38) {
		target_38.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_38.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_38.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_38.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_135
}

predicate func_39(Parameter vcontext_682, Variable vmessage_689, BlockStmt target_147, LogicalOrExpr target_39) {
		target_39.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="NegotiateKeyExchange"
		and target_39.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
		and target_39.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="Len"
		and target_39.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="EncryptedRandomSessionKey"
		and target_39.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_39.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="NegotiateKeyExchange"
		and target_39.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
		and target_39.getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="Len"
		and target_39.getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="EncryptedRandomSessionKey"
		and target_39.getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_39.getParent().(IfStmt).getThen()=target_147
}

predicate func_40(Variable vmessage_689, BlockStmt target_148, BitwiseAndExpr target_40) {
		target_40.getLeftOperand().(PointerFieldAccess).getTarget().getName()="NegotiateFlags"
		and target_40.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_40.getRightOperand().(Literal).getValue()="33554432"
		and target_40.getParent().(IfStmt).getThen()=target_148
}

predicate func_41(Variable vs_684, Variable vmessage_689, BlockStmt target_149, RelationalOperation target_41) {
		 (target_41 instanceof GTExpr or target_41 instanceof LTExpr)
		and target_41.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields_buffer")
		and target_41.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_41.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="DomainName"
		and target_41.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_41.getGreaterOperand().(Literal).getValue()="0"
		and target_41.getParent().(IfStmt).getThen()=target_149
}

predicate func_42(Variable vs_684, Variable vmessage_689, BlockStmt target_150, RelationalOperation target_42) {
		 (target_42 instanceof GTExpr or target_42 instanceof LTExpr)
		and target_42.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields_buffer")
		and target_42.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_42.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="UserName"
		and target_42.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_42.getGreaterOperand().(Literal).getValue()="0"
		and target_42.getParent().(IfStmt).getThen()=target_150
}

predicate func_43(Variable vs_684, Variable vmessage_689, BlockStmt target_151, RelationalOperation target_43) {
		 (target_43 instanceof GTExpr or target_43 instanceof LTExpr)
		and target_43.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields_buffer")
		and target_43.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_43.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="Workstation"
		and target_43.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_43.getGreaterOperand().(Literal).getValue()="0"
		and target_43.getParent().(IfStmt).getThen()=target_151
}

predicate func_44(Variable vs_684, Variable vmessage_689, BlockStmt target_152, RelationalOperation target_44) {
		 (target_44 instanceof GTExpr or target_44 instanceof LTExpr)
		and target_44.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields_buffer")
		and target_44.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_44.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="LmChallengeResponse"
		and target_44.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_44.getGreaterOperand().(Literal).getValue()="0"
		and target_44.getParent().(IfStmt).getThen()=target_152
}

predicate func_45(Variable vs_684, Variable vmessage_689, BlockStmt target_153, RelationalOperation target_45) {
		 (target_45 instanceof GTExpr or target_45 instanceof LTExpr)
		and target_45.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields_buffer")
		and target_45.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_45.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="NtChallengeResponse"
		and target_45.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_45.getGreaterOperand().(Literal).getValue()="0"
		and target_45.getParent().(IfStmt).getThen()=target_153
}

predicate func_46(Variable vmessage_689, BlockStmt target_154, RelationalOperation target_46) {
		 (target_46 instanceof GTExpr or target_46 instanceof LTExpr)
		and target_46.getGreaterOperand().(ValueFieldAccess).getTarget().getName()="Len"
		and target_46.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="NtChallengeResponse"
		and target_46.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_46.getLesserOperand().(Literal).getValue()="0"
		and target_46.getParent().(IfStmt).getThen()=target_154
}

predicate func_47(RelationalOperation target_46, Function func, DeclStmt target_47) {
		target_47.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_46
		and target_47.getEnclosingFunction() = func
}

predicate func_48(RelationalOperation target_46, Function func, DeclStmt target_48) {
		target_48.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_46
		and target_48.getEnclosingFunction() = func
}

predicate func_49(Variable vsnt_808, BlockStmt target_155, NotExpr target_49) {
		target_49.getOperand().(VariableAccess).getTarget()=vsnt_808
		and target_49.getParent().(IfStmt).getThen()=target_155
}

predicate func_50(Variable vs_684, RelationalOperation target_144, ExprStmt target_50) {
		target_50.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_50.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_50.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_50.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_144
}

predicate func_51(Variable vsnt_808, RelationalOperation target_144, ExprStmt target_51) {
		target_51.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_51.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsnt_808
		and target_51.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_51.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_144
}

predicate func_52(Parameter vcontext_682, Variable vmessage_689, RelationalOperation target_46, ExprStmt target_52) {
		target_52.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="pvBuffer"
		and target_52.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="NtChallengeResponse"
		and target_52.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
		and target_52.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="Buffer"
		and target_52.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="NtChallengeResponse"
		and target_52.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_52.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_46
}

predicate func_53(Parameter vcontext_682, Variable vmessage_689, RelationalOperation target_46, ExprStmt target_53) {
		target_53.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="cbBuffer"
		and target_53.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="NtChallengeResponse"
		and target_53.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
		and target_53.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="Len"
		and target_53.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="NtChallengeResponse"
		and target_53.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_53.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_46
}

predicate func_54(Parameter vcontext_682, RelationalOperation target_46, ExprStmt target_54) {
		target_54.getExpr().(FunctionCall).getTarget().hasName("sspi_SecBufferFree")
		and target_54.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ChallengeTargetInfo"
		and target_54.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
		and target_54.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_46
}

predicate func_55(Parameter vcontext_682, RelationalOperation target_46, ExprStmt target_55) {
		target_55.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="pvBuffer"
		and target_55.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ChallengeTargetInfo"
		and target_55.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
		and target_55.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="AvPairs"
		and target_55.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="Challenge"
		and target_55.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="NTLMv2Response"
		and target_55.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
		and target_55.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_46
}

predicate func_56(Parameter vcontext_682, Variable vmessage_689, RelationalOperation target_46, ExprStmt target_56) {
		target_56.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="cbBuffer"
		and target_56.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ChallengeTargetInfo"
		and target_56.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
		and target_56.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="Len"
		and target_56.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="NtChallengeResponse"
		and target_56.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_56.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(AddExpr).getValue()="44"
		and target_56.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_46
}

predicate func_57(Parameter vcontext_682, RelationalOperation target_46, ExprStmt target_57) {
		target_57.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_57.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ClientChallenge"
		and target_57.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
		and target_57.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="ClientChallenge"
		and target_57.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="Challenge"
		and target_57.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="NTLMv2Response"
		and target_57.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
		and target_57.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_57.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_46
}

predicate func_58(Parameter vcontext_682, Variable vAvFlags_687, Variable vcbAvFlags_807, RelationalOperation target_46, ExprStmt target_58) {
		target_58.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vAvFlags_687
		and target_58.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ntlm_av_pair_get")
		and target_58.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="AvPairs"
		and target_58.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="Challenge"
		and target_58.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="NTLMv2Response"
		and target_58.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
		and target_58.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="cbAvPairs"
		and target_58.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="Challenge"
		and target_58.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="NTLMv2Response"
		and target_58.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
		and target_58.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcbAvFlags_807
		and target_58.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_46
}

predicate func_59(Variable vflags_686, Variable vAvFlags_687, RelationalOperation target_46, IfStmt target_59) {
		target_59.getCondition().(VariableAccess).getTarget()=vAvFlags_687
		and target_59.getThen().(DoStmt).getCondition().(Literal).getValue()="0"
		and target_59.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vflags_686
		and target_59.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_46
}

predicate func_60(Variable vmessage_689, BlockStmt target_145, RelationalOperation target_60) {
		 (target_60 instanceof GTExpr or target_60 instanceof LTExpr)
		and target_60.getGreaterOperand().(ValueFieldAccess).getTarget().getName()="Len"
		and target_60.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="EncryptedRandomSessionKey"
		and target_60.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_60.getLesserOperand().(Literal).getValue()="0"
		and target_60.getParent().(IfStmt).getThen()=target_145
}

predicate func_61(Variable vmessage_689, BlockStmt target_156, EqualityOperation target_61) {
		target_61.getAnOperand().(ValueFieldAccess).getTarget().getName()="Len"
		and target_61.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="EncryptedRandomSessionKey"
		and target_61.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_61.getAnOperand().(Literal).getValue()="16"
		and target_61.getParent().(IfStmt).getThen()=target_156
}

predicate func_62(Parameter vcontext_682, Variable vmessage_689, RelationalOperation target_60, ExprStmt target_62) {
		target_62.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_62.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="EncryptedRandomSessionKey"
		and target_62.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
		and target_62.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="Buffer"
		and target_62.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="EncryptedRandomSessionKey"
		and target_62.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_62.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="16"
		and target_62.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_60
}

predicate func_63(Variable vlength_685, Parameter vcontext_682, BlockStmt target_157, NotExpr target_63) {
		target_63.getOperand().(FunctionCall).getTarget().hasName("sspi_SecBufferAlloc")
		and target_63.getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="AuthenticateMessage"
		and target_63.getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
		and target_63.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlength_685
		and target_63.getParent().(IfStmt).getThen()=target_157
}

predicate func_64(Variable vflags_686, BlockStmt target_158, BitwiseAndExpr target_64) {
		target_64.getLeftOperand().(VariableAccess).getTarget()=vflags_686
		and target_64.getRightOperand().(Literal).getValue()="2"
		and target_64.getParent().(IfStmt).getThen()=target_158
}

predicate func_65(Variable vs_684, Parameter vcontext_682, BitwiseAndExpr target_64, ExprStmt target_65) {
		target_65.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="MessageIntegrityCheckOffset"
		and target_65.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
		and target_65.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Stream_GetPosition")
		and target_65.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_65.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_64
}

predicate func_66(Variable vs_684, BlockStmt target_159, RelationalOperation target_66) {
		 (target_66 instanceof GTExpr or target_66 instanceof LTExpr)
		and target_66.getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_66.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_66.getGreaterOperand().(Literal).getValue()="16"
		and target_66.getParent().(IfStmt).getThen()=target_159
}

predicate func_67(Variable vs_684, Variable vmessage_689, BitwiseAndExpr target_64, ExprStmt target_67) {
		target_67.getExpr().(FunctionCall).getTarget().hasName("Stream_Read")
		and target_67.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_67.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="MessageIntegrityCheck"
		and target_67.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_67.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="16"
		and target_67.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_64
}

predicate func_68(Variable vmessage_689, Variable vcredentials_690, RelationalOperation target_160, ExprStmt target_68) {
		target_68.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="User"
		and target_68.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="identity"
		and target_68.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcredentials_690
		and target_68.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("malloc")
		and target_68.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="Len"
		and target_68.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="UserName"
		and target_68.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_68.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_160
}

predicate func_69(Variable vcredentials_690, BlockStmt target_161, NotExpr target_69) {
		target_69.getOperand().(ValueFieldAccess).getTarget().getName()="User"
		and target_69.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="identity"
		and target_69.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcredentials_690
		and target_69.getParent().(IfStmt).getThen()=target_161
}

predicate func_70(Variable vmessage_689, Variable vcredentials_690, RelationalOperation target_160, ExprStmt target_70) {
		target_70.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_70.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="User"
		and target_70.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="identity"
		and target_70.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcredentials_690
		and target_70.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="Buffer"
		and target_70.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="UserName"
		and target_70.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_70.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="Len"
		and target_70.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="UserName"
		and target_70.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_70.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_160
}

predicate func_71(Variable vmessage_689, Variable vcredentials_690, RelationalOperation target_160, ExprStmt target_71) {
		target_71.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="UserLength"
		and target_71.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="identity"
		and target_71.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcredentials_690
		and target_71.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="Len"
		and target_71.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="UserName"
		and target_71.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_71.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="2"
		and target_71.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_160
}

predicate func_72(Variable vmessage_689, BlockStmt target_162, RelationalOperation target_72) {
		 (target_72 instanceof GTExpr or target_72 instanceof LTExpr)
		and target_72.getGreaterOperand().(ValueFieldAccess).getTarget().getName()="Len"
		and target_72.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="DomainName"
		and target_72.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_72.getLesserOperand().(Literal).getValue()="0"
		and target_72.getParent().(IfStmt).getThen()=target_162
}

predicate func_73(Variable vmessage_689, Variable vcredentials_690, RelationalOperation target_72, ExprStmt target_73) {
		target_73.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="Domain"
		and target_73.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="identity"
		and target_73.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcredentials_690
		and target_73.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("malloc")
		and target_73.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="Len"
		and target_73.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="DomainName"
		and target_73.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_73.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_72
}

predicate func_74(Variable vcredentials_690, BlockStmt target_163, NotExpr target_74) {
		target_74.getOperand().(ValueFieldAccess).getTarget().getName()="Domain"
		and target_74.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="identity"
		and target_74.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcredentials_690
		and target_74.getParent().(IfStmt).getThen()=target_163
}

predicate func_75(Variable vmessage_689, Variable vcredentials_690, RelationalOperation target_72, ExprStmt target_75) {
		target_75.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_75.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="Domain"
		and target_75.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="identity"
		and target_75.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcredentials_690
		and target_75.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="Buffer"
		and target_75.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="DomainName"
		and target_75.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_75.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="Len"
		and target_75.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="DomainName"
		and target_75.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_75.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_72
}

predicate func_76(Variable vmessage_689, Variable vcredentials_690, RelationalOperation target_72, ExprStmt target_76) {
		target_76.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="DomainLength"
		and target_76.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="identity"
		and target_76.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcredentials_690
		and target_76.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="Len"
		and target_76.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="DomainName"
		and target_76.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_76.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="2"
		and target_76.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_72
}

predicate func_77(Parameter vcontext_682, Variable vsnt_808, FunctionCall target_77) {
		target_77.getTarget().hasName("ntlm_read_ntlm_v2_response")
		and target_77.getArgument(0).(VariableAccess).getTarget()=vsnt_808
		and target_77.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="NTLMv2Response"
		and target_77.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_682
}

predicate func_79(Variable vs_684, VariableAccess target_79) {
		target_79.getTarget()=vs_684
		and target_79.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_88(Variable vflags_686, AssignExpr target_88) {
		target_88.getLValue().(VariableAccess).getTarget()=vflags_686
		and target_88.getRValue() instanceof Literal
}

predicate func_89(Variable vAvFlags_687, AssignExpr target_89) {
		target_89.getLValue().(VariableAccess).getTarget()=vAvFlags_687
		and target_89.getRValue() instanceof Literal
}

predicate func_90(Variable vs_684, ExprStmt target_38, RelationalOperation target_137, FunctionCall target_90) {
		target_90.getTarget().hasName("Stream_Free")
		and target_90.getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_90.getArgument(1).(Literal).getValue()="0"
		and target_38.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_90.getArgument(0).(VariableAccess).getLocation())
		and target_90.getArgument(0).(VariableAccess).getLocation().isBefore(target_137.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_91(EqualityOperation target_136, Function func, ReturnStmt target_91) {
		target_91.getExpr() instanceof Literal
		and target_91.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_136
		and target_91.getEnclosingFunction() = func
}

predicate func_92(Variable vs_684, RelationalOperation target_137, RelationalOperation target_138, FunctionCall target_92) {
		target_92.getTarget().hasName("Stream_Free")
		and target_92.getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_92.getArgument(1).(Literal).getValue()="0"
		and target_137.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_92.getArgument(0).(VariableAccess).getLocation())
		and target_92.getArgument(0).(VariableAccess).getLocation().isBefore(target_138.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_93(RelationalOperation target_137, Function func, ReturnStmt target_93) {
		target_93.getExpr() instanceof Literal
		and target_93.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_137
		and target_93.getEnclosingFunction() = func
}

predicate func_94(Variable vs_684, RelationalOperation target_138, RelationalOperation target_139, FunctionCall target_94) {
		target_94.getTarget().hasName("Stream_Free")
		and target_94.getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_94.getArgument(1).(Literal).getValue()="0"
		and target_138.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_94.getArgument(0).(VariableAccess).getLocation())
		and target_94.getArgument(0).(VariableAccess).getLocation().isBefore(target_139.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_95(RelationalOperation target_138, Function func, ReturnStmt target_95) {
		target_95.getExpr().(Literal).getValue()="2148074248"
		and target_95.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_138
		and target_95.getEnclosingFunction() = func
}

predicate func_96(Variable vs_684, RelationalOperation target_139, RelationalOperation target_140, ExprStmt target_96) {
		target_96.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_96.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_96.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_96.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_139
		and target_96.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_140.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_97(RelationalOperation target_139, Function func, ReturnStmt target_97) {
		target_97.getExpr().(Literal).getValue()="2148074248"
		and target_97.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_139
		and target_97.getEnclosingFunction() = func
}

predicate func_98(Variable vs_684, RelationalOperation target_140, RelationalOperation target_141, ExprStmt target_98) {
		target_98.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_98.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_98.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_98.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_140
		and target_98.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_141.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_99(RelationalOperation target_140, Function func, ReturnStmt target_99) {
		target_99.getExpr().(Literal).getValue()="2148074248"
		and target_99.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_140
		and target_99.getEnclosingFunction() = func
}

predicate func_100(Variable vs_684, RelationalOperation target_141, RelationalOperation target_142, ExprStmt target_100) {
		target_100.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_100.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_100.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_100.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_141
		and target_100.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_142.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_101(RelationalOperation target_141, Function func, ReturnStmt target_101) {
		target_101.getExpr().(Literal).getValue()="2148074248"
		and target_101.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_141
		and target_101.getEnclosingFunction() = func
}

predicate func_102(Variable vs_684, RelationalOperation target_142, ExprStmt target_102) {
		target_102.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_102.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_102.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_102.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_142
}

predicate func_103(RelationalOperation target_142, Function func, ReturnStmt target_103) {
		target_103.getExpr().(Literal).getValue()="2148074248"
		and target_103.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_142
		and target_103.getEnclosingFunction() = func
}

predicate func_104(Variable vs_684, LogicalOrExpr target_39, ExprStmt target_165, RelationalOperation target_143, ExprStmt target_104) {
		target_104.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_104.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_104.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_104.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
		and target_165.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_104.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_104.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_143.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_105(LogicalOrExpr target_39, Function func, ReturnStmt target_105) {
		target_105.getExpr().(Literal).getValue()="2148074248"
		and target_105.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
		and target_105.getEnclosingFunction() = func
}

predicate func_106(Variable vs_684, RelationalOperation target_143, ExprStmt target_166, ExprStmt target_106) {
		target_106.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_106.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_106.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_106.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_143
		and target_106.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_166.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_107(RelationalOperation target_143, Function func, ReturnStmt target_107) {
		target_107.getExpr().(Literal).getValue()="2148074248"
		and target_107.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_143
		and target_107.getEnclosingFunction() = func
}

predicate func_108(Variable vs_684, RelationalOperation target_41, RelationalOperation target_42, ExprStmt target_108) {
		target_108.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_108.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_108.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_108.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_41
		and target_108.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_42.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_109(RelationalOperation target_41, Function func, ReturnStmt target_109) {
		target_109.getExpr() instanceof Literal
		and target_109.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_41
		and target_109.getEnclosingFunction() = func
}

predicate func_110(Variable vs_684, RelationalOperation target_42, RelationalOperation target_43, ExprStmt target_110) {
		target_110.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_110.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_110.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_110.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_42
		and target_110.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_43.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_111(RelationalOperation target_42, Function func, ReturnStmt target_111) {
		target_111.getExpr() instanceof Literal
		and target_111.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_42
		and target_111.getEnclosingFunction() = func
}

predicate func_112(Variable vs_684, RelationalOperation target_43, RelationalOperation target_44, ExprStmt target_112) {
		target_112.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_112.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_112.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_112.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_43
		and target_112.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_44.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_113(RelationalOperation target_43, Function func, ReturnStmt target_113) {
		target_113.getExpr() instanceof Literal
		and target_113.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_43
		and target_113.getEnclosingFunction() = func
}

predicate func_114(Variable vs_684, RelationalOperation target_44, RelationalOperation target_45, ExprStmt target_114) {
		target_114.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_114.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_114.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_114.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
		and target_114.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_45.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_115(RelationalOperation target_44, Function func, ReturnStmt target_115) {
		target_115.getExpr().(Literal).getValue()="2148074244"
		and target_115.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
		and target_115.getEnclosingFunction() = func
}

predicate func_116(Variable vs_684, RelationalOperation target_45, ExprStmt target_118, ExprStmt target_116) {
		target_116.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_116.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_116.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_116.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_45
		and target_116.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_118.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_117(RelationalOperation target_45, Function func, ReturnStmt target_117) {
		target_117.getExpr().(Literal).getValue()="2148074244"
		and target_117.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_45
		and target_117.getEnclosingFunction() = func
}

predicate func_118(Variable vs_684, NotExpr target_49, ExprStmt target_116, ExprStmt target_50, ExprStmt target_118) {
		target_118.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_118.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_118.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_118.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_49
		and target_116.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_118.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_118.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_50.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_119(NotExpr target_49, Function func, ReturnStmt target_119) {
		target_119.getExpr().(Literal).getValue()="2148074244"
		and target_119.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_49
		and target_119.getEnclosingFunction() = func
}

predicate func_120(RelationalOperation target_144, Function func, ReturnStmt target_120) {
		target_120.getExpr().(Literal).getValue()="2148074248"
		and target_120.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_144
		and target_120.getEnclosingFunction() = func
}

predicate func_121(Variable vsnt_808, ExprStmt target_51, FunctionCall target_121) {
		target_121.getTarget().hasName("Stream_Free")
		and target_121.getArgument(0).(VariableAccess).getTarget()=vsnt_808
		and target_121.getArgument(1).(Literal).getValue()="0"
		and target_51.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_121.getArgument(0).(VariableAccess).getLocation())
}

predicate func_122(Variable vs_684, RelationalOperation target_146, ExprStmt target_124, ExprStmt target_122) {
		target_122.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_122.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_122.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_122.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_146
		and target_122.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_124.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_123(RelationalOperation target_146, Function func, ReturnStmt target_123) {
		target_123.getExpr().(Literal).getValue()="2148074244"
		and target_123.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_146
		and target_123.getEnclosingFunction() = func
}

predicate func_124(Variable vs_684, EqualityOperation target_61, ExprStmt target_122, ExprStmt target_167, ExprStmt target_124) {
		target_124.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_124.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_124.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_124.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_61
		and target_122.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_124.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_124.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_167.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_125(EqualityOperation target_61, Function func, ReturnStmt target_125) {
		target_125.getExpr().(Literal).getValue()="2148074248"
		and target_125.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_61
		and target_125.getEnclosingFunction() = func
}

predicate func_126(Variable vs_684, NotExpr target_63, ExprStmt target_167, FunctionCall target_168, ExprStmt target_126) {
		target_126.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_126.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_126.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_126.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_63
		and target_167.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_126.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_126.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_168.getArgument(0).(VariableAccess).getLocation())
}

predicate func_127(NotExpr target_63, Function func, ReturnStmt target_127) {
		target_127.getExpr().(Literal).getValue()="2148074244"
		and target_127.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_63
		and target_127.getEnclosingFunction() = func
}

predicate func_128(Variable vs_684, RelationalOperation target_66, ExprStmt target_67, ExprStmt target_128) {
		target_128.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_128.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_128.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_128.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_66
		and target_128.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_67.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_129(RelationalOperation target_66, Function func, ReturnStmt target_129) {
		target_129.getExpr().(Literal).getValue()="2148074248"
		and target_129.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_66
		and target_129.getEnclosingFunction() = func
}

predicate func_130(Variable vs_684, NotExpr target_69, ExprStmt target_67, ExprStmt target_132, ExprStmt target_130) {
		target_130.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_130.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_130.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_130.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_69
		and target_67.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_130.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_130.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_132.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_131(NotExpr target_69, Function func, ReturnStmt target_131) {
		target_131.getExpr().(Literal).getValue()="2148074244"
		and target_131.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_69
		and target_131.getEnclosingFunction() = func
}

predicate func_132(Variable vs_684, NotExpr target_74, ExprStmt target_130, ExprStmt target_134, ExprStmt target_132) {
		target_132.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_132.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_132.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_132.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_74
		and target_130.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_132.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_132.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_134.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_133(NotExpr target_74, Function func, ReturnStmt target_133) {
		target_133.getExpr().(Literal).getValue()="2148074244"
		and target_133.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_74
		and target_133.getEnclosingFunction() = func
}

predicate func_134(Variable vs_684, ExprStmt target_132, Function func, ExprStmt target_134) {
		target_134.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_134.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_134.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_134
		and target_132.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_134.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_135(Variable vs_684, Variable vmessage_689, RelationalOperation target_135) {
		 (target_135 instanceof GTExpr or target_135 instanceof LTExpr)
		and target_135.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_header")
		and target_135.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_135.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmessage_689
		and target_135.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_136(Variable vmessage_689, EqualityOperation target_136) {
		target_136.getAnOperand().(PointerFieldAccess).getTarget().getName()="MessageType"
		and target_136.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_136.getAnOperand().(Literal).getValue()="3"
}

predicate func_137(Variable vs_684, Variable vmessage_689, RelationalOperation target_137) {
		 (target_137 instanceof GTExpr or target_137 instanceof LTExpr)
		and target_137.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields")
		and target_137.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_137.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="LmChallengeResponse"
		and target_137.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_137.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_138(Variable vs_684, Variable vmessage_689, RelationalOperation target_138) {
		 (target_138 instanceof GTExpr or target_138 instanceof LTExpr)
		and target_138.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields")
		and target_138.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_138.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="NtChallengeResponse"
		and target_138.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_138.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_139(Variable vs_684, Variable vmessage_689, RelationalOperation target_139) {
		 (target_139 instanceof GTExpr or target_139 instanceof LTExpr)
		and target_139.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields")
		and target_139.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_139.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="DomainName"
		and target_139.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_139.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_140(Variable vs_684, Variable vmessage_689, RelationalOperation target_140) {
		 (target_140 instanceof GTExpr or target_140 instanceof LTExpr)
		and target_140.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields")
		and target_140.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_140.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="UserName"
		and target_140.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_140.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_141(Variable vs_684, Variable vmessage_689, RelationalOperation target_141) {
		 (target_141 instanceof GTExpr or target_141 instanceof LTExpr)
		and target_141.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields")
		and target_141.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_141.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="Workstation"
		and target_141.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_141.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_142(Variable vs_684, Variable vmessage_689, RelationalOperation target_142) {
		 (target_142 instanceof GTExpr or target_142 instanceof LTExpr)
		and target_142.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields")
		and target_142.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_142.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="EncryptedRandomSessionKey"
		and target_142.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_142.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_143(Variable vs_684, Variable vmessage_689, RelationalOperation target_143) {
		 (target_143 instanceof GTExpr or target_143 instanceof LTExpr)
		and target_143.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_version_info")
		and target_143.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_143.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="Version"
		and target_143.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_143.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_144(RelationalOperation target_144) {
		 (target_144 instanceof GTExpr or target_144 instanceof LTExpr)
		and target_144.getLesserOperand() instanceof FunctionCall
		and target_144.getGreaterOperand() instanceof Literal
}

predicate func_145(BlockStmt target_145) {
		target_145.getStmt(0).(IfStmt).getCondition() instanceof EqualityOperation
		and target_145.getStmt(0).(IfStmt).getThen() instanceof BlockStmt
		and target_145.getStmt(1) instanceof ExprStmt
}

predicate func_146(Variable vs_684, Variable vmessage_689, RelationalOperation target_146) {
		 (target_146 instanceof GTExpr or target_146 instanceof LTExpr)
		and target_146.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields_buffer")
		and target_146.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_146.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="EncryptedRandomSessionKey"
		and target_146.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_146.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_147(BlockStmt target_147) {
		target_147.getStmt(0) instanceof ExprStmt
		and target_147.getStmt(1) instanceof ReturnStmt
}

predicate func_148(Variable vs_684, Variable vmessage_689, BlockStmt target_148) {
		target_148.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_version_info")
		and target_148.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_148.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="Version"
		and target_148.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_148.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_148.getStmt(0).(IfStmt).getThen() instanceof BlockStmt
}

predicate func_149(BlockStmt target_149) {
		target_149.getStmt(0) instanceof ExprStmt
		and target_149.getStmt(1) instanceof ReturnStmt
}

predicate func_150(BlockStmt target_150) {
		target_150.getStmt(0) instanceof ExprStmt
		and target_150.getStmt(1) instanceof ReturnStmt
}

predicate func_151(BlockStmt target_151) {
		target_151.getStmt(0) instanceof ExprStmt
		and target_151.getStmt(1) instanceof ReturnStmt
}

predicate func_152(BlockStmt target_152) {
		target_152.getStmt(0) instanceof ExprStmt
		and target_152.getStmt(1) instanceof ReturnStmt
}

predicate func_153(BlockStmt target_153) {
		target_153.getStmt(0) instanceof ExprStmt
		and target_153.getStmt(1) instanceof ReturnStmt
}

predicate func_154(BlockStmt target_154) {
		target_154.getStmt(2).(IfStmt).getCondition() instanceof NotExpr
		and target_154.getStmt(2).(IfStmt).getThen() instanceof BlockStmt
		and target_154.getStmt(3).(IfStmt).getCondition().(RelationalOperation).getLesserOperand() instanceof FunctionCall
		and target_154.getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_154.getStmt(3).(IfStmt).getThen() instanceof BlockStmt
}

predicate func_155(BlockStmt target_155) {
		target_155.getStmt(0) instanceof ExprStmt
		and target_155.getStmt(1) instanceof ReturnStmt
}

predicate func_156(BlockStmt target_156) {
		target_156.getStmt(0) instanceof ExprStmt
		and target_156.getStmt(1) instanceof ReturnStmt
}

predicate func_157(BlockStmt target_157) {
		target_157.getStmt(0) instanceof ExprStmt
		and target_157.getStmt(1) instanceof ReturnStmt
}

predicate func_158(BlockStmt target_158) {
		target_158.getStmt(0) instanceof ExprStmt
		and target_158.getStmt(1).(IfStmt).getCondition() instanceof RelationalOperation
		and target_158.getStmt(1).(IfStmt).getThen() instanceof BlockStmt
		and target_158.getStmt(2) instanceof ExprStmt
}

predicate func_159(BlockStmt target_159) {
		target_159.getStmt(0) instanceof ExprStmt
		and target_159.getStmt(1) instanceof ReturnStmt
}

predicate func_160(Variable vmessage_689, RelationalOperation target_160) {
		 (target_160 instanceof GTExpr or target_160 instanceof LTExpr)
		and target_160.getGreaterOperand().(ValueFieldAccess).getTarget().getName()="Len"
		and target_160.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="UserName"
		and target_160.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_689
		and target_160.getLesserOperand().(Literal).getValue()="0"
}

predicate func_161(BlockStmt target_161) {
		target_161.getStmt(0) instanceof ExprStmt
		and target_161.getStmt(1) instanceof ReturnStmt
}

predicate func_162(BlockStmt target_162) {
		target_162.getStmt(0) instanceof ExprStmt
		and target_162.getStmt(1).(IfStmt).getCondition() instanceof NotExpr
		and target_162.getStmt(1).(IfStmt).getThen() instanceof BlockStmt
		and target_162.getStmt(2) instanceof ExprStmt
		and target_162.getStmt(3) instanceof ExprStmt
}

predicate func_163(BlockStmt target_163) {
		target_163.getStmt(0) instanceof ExprStmt
		and target_163.getStmt(1) instanceof ReturnStmt
}

predicate func_165(Variable vs_684, ExprStmt target_165) {
		target_165.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_165.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
		and target_165.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_165.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="4"
}

predicate func_166(Variable vs_684, ExprStmt target_166) {
		target_166.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Stream_GetPosition")
		and target_166.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
}

predicate func_167(Variable vs_684, Variable vlength_685, ExprStmt target_167) {
		target_167.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlength_685
		and target_167.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Stream_GetPosition")
		and target_167.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_684
}

predicate func_168(Variable vs_684, FunctionCall target_168) {
		target_168.getTarget().hasName("Stream_Buffer")
		and target_168.getArgument(0).(VariableAccess).getTarget()=vs_684
}

from Function func, Variable vs_684, Variable vlength_685, Parameter vcontext_682, Variable vflags_686, Variable vAvFlags_687, Variable vmessage_689, Variable vcredentials_690, Variable vcbAvFlags_807, Variable vsnt_808, ExprStmt target_38, LogicalOrExpr target_39, BitwiseAndExpr target_40, RelationalOperation target_41, RelationalOperation target_42, RelationalOperation target_43, RelationalOperation target_44, RelationalOperation target_45, RelationalOperation target_46, DeclStmt target_47, DeclStmt target_48, NotExpr target_49, ExprStmt target_50, ExprStmt target_51, ExprStmt target_52, ExprStmt target_53, ExprStmt target_54, ExprStmt target_55, ExprStmt target_56, ExprStmt target_57, ExprStmt target_58, IfStmt target_59, RelationalOperation target_60, EqualityOperation target_61, ExprStmt target_62, NotExpr target_63, BitwiseAndExpr target_64, ExprStmt target_65, RelationalOperation target_66, ExprStmt target_67, ExprStmt target_68, NotExpr target_69, ExprStmt target_70, ExprStmt target_71, RelationalOperation target_72, ExprStmt target_73, NotExpr target_74, ExprStmt target_75, ExprStmt target_76, FunctionCall target_77, VariableAccess target_79, AssignExpr target_88, AssignExpr target_89, FunctionCall target_90, ReturnStmt target_91, FunctionCall target_92, ReturnStmt target_93, FunctionCall target_94, ReturnStmt target_95, ExprStmt target_96, ReturnStmt target_97, ExprStmt target_98, ReturnStmt target_99, ExprStmt target_100, ReturnStmt target_101, ExprStmt target_102, ReturnStmt target_103, ExprStmt target_104, ReturnStmt target_105, ExprStmt target_106, ReturnStmt target_107, ExprStmt target_108, ReturnStmt target_109, ExprStmt target_110, ReturnStmt target_111, ExprStmt target_112, ReturnStmt target_113, ExprStmt target_114, ReturnStmt target_115, ExprStmt target_116, ReturnStmt target_117, ExprStmt target_118, ReturnStmt target_119, ReturnStmt target_120, FunctionCall target_121, ExprStmt target_122, ReturnStmt target_123, ExprStmt target_124, ReturnStmt target_125, ExprStmt target_126, ReturnStmt target_127, ExprStmt target_128, ReturnStmt target_129, ExprStmt target_130, ReturnStmt target_131, ExprStmt target_132, ReturnStmt target_133, ExprStmt target_134, RelationalOperation target_135, EqualityOperation target_136, RelationalOperation target_137, RelationalOperation target_138, RelationalOperation target_139, RelationalOperation target_140, RelationalOperation target_141, RelationalOperation target_142, RelationalOperation target_143, RelationalOperation target_144, BlockStmt target_145, RelationalOperation target_146, BlockStmt target_147, BlockStmt target_148, BlockStmt target_149, BlockStmt target_150, BlockStmt target_151, BlockStmt target_152, BlockStmt target_153, BlockStmt target_154, BlockStmt target_155, BlockStmt target_156, BlockStmt target_157, BlockStmt target_158, BlockStmt target_159, RelationalOperation target_160, BlockStmt target_161, BlockStmt target_162, BlockStmt target_163, ExprStmt target_165, ExprStmt target_166, ExprStmt target_167, FunctionCall target_168
where
not func_1(func)
and not func_2(func)
and not func_3(target_135, func)
and not func_4(target_136, func)
and not func_5(target_137, func)
and not func_6(target_138, func)
and not func_7(target_139, func)
and not func_8(target_140, func)
and not func_9(target_141, func)
and not func_10(target_142, func)
and not func_11(vs_684, target_38, target_137)
and not func_13(target_39, func)
and not func_14(target_40, func)
and not func_15(target_143, func)
and not func_16(func)
and not func_17(target_42, func)
and not func_18(target_43, func)
and not func_19(target_44, func)
and not func_20(target_45, func)
and not func_21(target_46, func)
and not func_22(target_144, func)
and not func_23(func)
and not func_24(func)
and not func_25(target_145, func)
and not func_26(target_60, func)
and not func_27(func)
and not func_28(target_146, func)
and not func_29(target_63, func)
and not func_30(target_64, func)
and not func_31(func)
and not func_32(target_69, func)
and not func_33(func)
and not func_34(target_72, func)
and not func_35(target_140, func)
and not func_36(func)
and func_38(vs_684, target_135, target_38)
and func_39(vcontext_682, vmessage_689, target_147, target_39)
and func_40(vmessage_689, target_148, target_40)
and func_41(vs_684, vmessage_689, target_149, target_41)
and func_42(vs_684, vmessage_689, target_150, target_42)
and func_43(vs_684, vmessage_689, target_151, target_43)
and func_44(vs_684, vmessage_689, target_152, target_44)
and func_45(vs_684, vmessage_689, target_153, target_45)
and func_46(vmessage_689, target_154, target_46)
and func_47(target_46, func, target_47)
and func_48(target_46, func, target_48)
and func_49(vsnt_808, target_155, target_49)
and func_50(vs_684, target_144, target_50)
and func_51(vsnt_808, target_144, target_51)
and func_52(vcontext_682, vmessage_689, target_46, target_52)
and func_53(vcontext_682, vmessage_689, target_46, target_53)
and func_54(vcontext_682, target_46, target_54)
and func_55(vcontext_682, target_46, target_55)
and func_56(vcontext_682, vmessage_689, target_46, target_56)
and func_57(vcontext_682, target_46, target_57)
and func_58(vcontext_682, vAvFlags_687, vcbAvFlags_807, target_46, target_58)
and func_59(vflags_686, vAvFlags_687, target_46, target_59)
and func_60(vmessage_689, target_145, target_60)
and func_61(vmessage_689, target_156, target_61)
and func_62(vcontext_682, vmessage_689, target_60, target_62)
and func_63(vlength_685, vcontext_682, target_157, target_63)
and func_64(vflags_686, target_158, target_64)
and func_65(vs_684, vcontext_682, target_64, target_65)
and func_66(vs_684, target_159, target_66)
and func_67(vs_684, vmessage_689, target_64, target_67)
and func_68(vmessage_689, vcredentials_690, target_160, target_68)
and func_69(vcredentials_690, target_161, target_69)
and func_70(vmessage_689, vcredentials_690, target_160, target_70)
and func_71(vmessage_689, vcredentials_690, target_160, target_71)
and func_72(vmessage_689, target_162, target_72)
and func_73(vmessage_689, vcredentials_690, target_72, target_73)
and func_74(vcredentials_690, target_163, target_74)
and func_75(vmessage_689, vcredentials_690, target_72, target_75)
and func_76(vmessage_689, vcredentials_690, target_72, target_76)
and func_77(vcontext_682, vsnt_808, target_77)
and func_79(vs_684, target_79)
and func_88(vflags_686, target_88)
and func_89(vAvFlags_687, target_89)
and func_90(vs_684, target_38, target_137, target_90)
and func_91(target_136, func, target_91)
and func_92(vs_684, target_137, target_138, target_92)
and func_93(target_137, func, target_93)
and func_94(vs_684, target_138, target_139, target_94)
and func_95(target_138, func, target_95)
and func_96(vs_684, target_139, target_140, target_96)
and func_97(target_139, func, target_97)
and func_98(vs_684, target_140, target_141, target_98)
and func_99(target_140, func, target_99)
and func_100(vs_684, target_141, target_142, target_100)
and func_101(target_141, func, target_101)
and func_102(vs_684, target_142, target_102)
and func_103(target_142, func, target_103)
and func_104(vs_684, target_39, target_165, target_143, target_104)
and func_105(target_39, func, target_105)
and func_106(vs_684, target_143, target_166, target_106)
and func_107(target_143, func, target_107)
and func_108(vs_684, target_41, target_42, target_108)
and func_109(target_41, func, target_109)
and func_110(vs_684, target_42, target_43, target_110)
and func_111(target_42, func, target_111)
and func_112(vs_684, target_43, target_44, target_112)
and func_113(target_43, func, target_113)
and func_114(vs_684, target_44, target_45, target_114)
and func_115(target_44, func, target_115)
and func_116(vs_684, target_45, target_118, target_116)
and func_117(target_45, func, target_117)
and func_118(vs_684, target_49, target_116, target_50, target_118)
and func_119(target_49, func, target_119)
and func_120(target_144, func, target_120)
and func_121(vsnt_808, target_51, target_121)
and func_122(vs_684, target_146, target_124, target_122)
and func_123(target_146, func, target_123)
and func_124(vs_684, target_61, target_122, target_167, target_124)
and func_125(target_61, func, target_125)
and func_126(vs_684, target_63, target_167, target_168, target_126)
and func_127(target_63, func, target_127)
and func_128(vs_684, target_66, target_67, target_128)
and func_129(target_66, func, target_129)
and func_130(vs_684, target_69, target_67, target_132, target_130)
and func_131(target_69, func, target_131)
and func_132(vs_684, target_74, target_130, target_134, target_132)
and func_133(target_74, func, target_133)
and func_134(vs_684, target_132, func, target_134)
and func_135(vs_684, vmessage_689, target_135)
and func_136(vmessage_689, target_136)
and func_137(vs_684, vmessage_689, target_137)
and func_138(vs_684, vmessage_689, target_138)
and func_139(vs_684, vmessage_689, target_139)
and func_140(vs_684, vmessage_689, target_140)
and func_141(vs_684, vmessage_689, target_141)
and func_142(vs_684, vmessage_689, target_142)
and func_143(vs_684, vmessage_689, target_143)
and func_144(target_144)
and func_145(target_145)
and func_146(vs_684, vmessage_689, target_146)
and func_147(target_147)
and func_148(vs_684, vmessage_689, target_148)
and func_149(target_149)
and func_150(target_150)
and func_151(target_151)
and func_152(target_152)
and func_153(target_153)
and func_154(target_154)
and func_155(target_155)
and func_156(target_156)
and func_157(target_157)
and func_158(target_158)
and func_159(target_159)
and func_160(vmessage_689, target_160)
and func_161(target_161)
and func_162(target_162)
and func_163(target_163)
and func_165(vs_684, target_165)
and func_166(vs_684, target_166)
and func_167(vs_684, vlength_685, target_167)
and func_168(vs_684, target_168)
and vs_684.getType().hasName("wStream *")
and vlength_685.getType().hasName("size_t")
and vcontext_682.getType().hasName("NTLM_CONTEXT *")
and vflags_686.getType().hasName("UINT32")
and vAvFlags_687.getType().hasName("NTLM_AV_PAIR *")
and vmessage_689.getType().hasName("NTLM_AUTHENTICATE_MESSAGE *")
and vcredentials_690.getType().hasName("SSPI_CREDENTIALS *")
and vcbAvFlags_807.getType().hasName("size_t")
and vsnt_808.getType().hasName("wStream *")
and vs_684.getParentScope+() = func
and vlength_685.getParentScope+() = func
and vcontext_682.getParentScope+() = func
and vflags_686.getParentScope+() = func
and vAvFlags_687.getParentScope+() = func
and vmessage_689.getParentScope+() = func
and vcredentials_690.getParentScope+() = func
and vcbAvFlags_807.getParentScope+() = func
and vsnt_808.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
