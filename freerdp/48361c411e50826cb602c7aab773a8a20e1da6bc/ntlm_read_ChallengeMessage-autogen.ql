/**
 * @name freerdp-48361c411e50826cb602c7aab773a8a20e1da6bc-ntlm_read_ChallengeMessage
 * @id cpp/freerdp/48361c411e50826cb602c7aab773a8a20e1da6bc/ntlm-read-ChallengeMessage
 * @description freerdp-48361c411e50826cb602c7aab773a8a20e1da6bc-winpr/libwinpr/sspi/NTLM/ntlm_message.c-ntlm_read_ChallengeMessage CVE-2020-13396
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_370, FunctionCall target_0) {
		target_0.getTarget().hasName("Stream_Pointer")
		and not target_0.getTarget().hasName("Stream_Buffer")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vs_370
}

predicate func_4(Parameter vcontext_368, Parameter vbuffer_368, BlockStmt target_101, ExprStmt target_102, ExprStmt target_103, ExprStmt target_104) {
	exists(LogicalOrExpr target_4 |
		target_4.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vcontext_368
		and target_4.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vbuffer_368
		and target_4.getParent().(IfStmt).getThen()=target_101
		and target_102.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation())
		and target_4.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_103.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_104.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vs_370, Variable vStartOffset_372, ExprStmt target_33, RelationalOperation target_35) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getTarget()=vStartOffset_372
		and target_5.getRValue().(FunctionCall).getTarget().hasName("Stream_GetPosition")
		and target_5.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_33.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_35.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(EqualityOperation target_34, Function func) {
	exists(GotoStmt target_6 |
		target_6.toString() = "goto ..."
		and target_6.getName() ="fail"
		and target_6.getParent().(IfStmt).getCondition()=target_34
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(RelationalOperation target_35, Function func) {
	exists(GotoStmt target_7 |
		target_7.toString() = "goto ..."
		and target_7.getName() ="fail"
		and target_7.getParent().(IfStmt).getCondition()=target_35
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(RelationalOperation target_36, Function func) {
	exists(GotoStmt target_8 |
		target_8.toString() = "goto ..."
		and target_8.getName() ="fail"
		and target_8.getParent().(IfStmt).getCondition()=target_36
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(RelationalOperation target_37, Function func) {
	exists(GotoStmt target_9 |
		target_9.toString() = "goto ..."
		and target_9.getName() ="fail"
		and target_9.getParent().(IfStmt).getCondition()=target_37
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(RelationalOperation target_38, Function func) {
	exists(GotoStmt target_10 |
		target_10.toString() = "goto ..."
		and target_10.getName() ="fail"
		and target_10.getParent().(IfStmt).getCondition()=target_38
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(RelationalOperation target_39, Function func) {
	exists(GotoStmt target_11 |
		target_11.toString() = "goto ..."
		and target_11.getName() ="fail"
		and target_11.getParent().(IfStmt).getCondition()=target_39
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(BitwiseAndExpr target_40, Function func) {
	exists(GotoStmt target_12 |
		target_12.toString() = "goto ..."
		and target_12.getName() ="fail"
		and target_12.getParent().(IfStmt).getCondition()=target_40
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(RelationalOperation target_105, Function func) {
	exists(GotoStmt target_13 |
		target_13.toString() = "goto ..."
		and target_13.getName() ="fail"
		and target_13.getParent().(IfStmt).getCondition()=target_105
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Variable vs_370, Variable vPayloadOffset_373, RelationalOperation target_35, RelationalOperation target_36) {
	exists(AssignExpr target_14 |
		target_14.getLValue().(VariableAccess).getTarget()=vPayloadOffset_373
		and target_14.getRValue().(FunctionCall).getTarget().hasName("Stream_GetPosition")
		and target_14.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_35.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_14.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_14.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_36.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_15(Function func) {
	exists(AssignExpr target_15 |
		target_15.getLValue().(VariableAccess).getType().hasName("SECURITY_STATUS")
		and target_15.getRValue() instanceof Literal
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(RelationalOperation target_106, Function func) {
	exists(GotoStmt target_16 |
		target_16.toString() = "goto ..."
		and target_16.getName() ="fail"
		and target_16.getParent().(IfStmt).getCondition()=target_106
		and target_16.getEnclosingFunction() = func)
}

predicate func_17(VariableAccess target_65, Function func) {
	exists(GotoStmt target_17 |
		target_17.toString() = "goto ..."
		and target_17.getName() ="fail"
		and target_17.getParent().(IfStmt).getCondition()=target_65
		and target_17.getEnclosingFunction() = func)
}

predicate func_18(RelationalOperation target_53, Function func) {
	exists(GotoStmt target_18 |
		target_18.toString() = "goto ..."
		and target_18.getName() ="fail"
		and target_18.getParent().(IfStmt).getCondition()=target_53
		and target_18.getEnclosingFunction() = func)
}

predicate func_19(Variable vlength_371, Variable vStartOffset_372, Variable vPayloadOffset_373, NotExpr target_61) {
	exists(AssignExpr target_19 |
		target_19.getLValue().(VariableAccess).getTarget()=vlength_371
		and target_19.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vPayloadOffset_373
		and target_19.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vStartOffset_372
		and target_19.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand() instanceof ValueFieldAccess
		and target_19.getRValue().(AddExpr).getAnOperand() instanceof ValueFieldAccess
		and target_61.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_19.getLValue().(VariableAccess).getLocation()))
}

predicate func_20(Parameter vbuffer_368, Variable vlength_371, BlockStmt target_109, NotExpr target_61) {
	exists(RelationalOperation target_20 |
		 (target_20 instanceof GTExpr or target_20 instanceof LTExpr)
		and target_20.getGreaterOperand().(VariableAccess).getTarget()=vlength_371
		and target_20.getLesserOperand().(PointerFieldAccess).getTarget().getName()="cbBuffer"
		and target_20.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuffer_368
		and target_20.getParent().(IfStmt).getThen()=target_109
		and target_20.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_61.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_21(NotExpr target_61, Function func) {
	exists(GotoStmt target_21 |
		target_21.toString() = "goto ..."
		and target_21.getName() ="fail"
		and target_21.getParent().(IfStmt).getCondition()=target_61
		and target_21.getEnclosingFunction() = func)
}

predicate func_22(PointerFieldAccess target_52, Function func) {
	exists(GotoStmt target_22 |
		target_22.toString() = "goto ..."
		and target_22.getName() ="fail"
		and target_22.getParent().(IfStmt).getCondition()=target_52
		and target_22.getEnclosingFunction() = func)
}

predicate func_23(Parameter vcontext_368, ExprStmt target_111, RelationalOperation target_57) {
	exists(ValueFieldAccess target_23 |
		target_23.getTarget().getName()="pvBuffer"
		and target_23.getQualifier().(PointerFieldAccess).getTarget().getName()="ChallengeMessage"
		and target_23.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_111.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_23.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_23.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_57.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_24(Parameter vcontext_368, Variable vs_370, Variable vlength_371, Variable vStartOffset_372, NotExpr target_112, RelationalOperation target_32, ExprStmt target_113) {
	exists(PointerArithmeticOperation target_24 |
		target_24.getAnOperand().(FunctionCall).getTarget().hasName("Stream_Buffer")
		and target_24.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_24.getAnOperand().(VariableAccess).getTarget()=vStartOffset_372
		and target_24.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_24.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="pvBuffer"
		and target_24.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ChallengeMessage"
		and target_24.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_24.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vStartOffset_372
		and target_24.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlength_371
		and target_112.getOperand().(VariableAccess).getLocation().isBefore(target_24.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_24.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_32.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_24.getAnOperand().(VariableAccess).getLocation().isBefore(target_113.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_26(RelationalOperation target_37, Function func) {
	exists(IfStmt target_26 |
		target_26.getCondition() instanceof RelationalOperation
		and target_26.getThen().(GotoStmt).toString() = "goto ..."
		and target_26.getThen().(GotoStmt).getName() ="fail"
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_26
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_37
		and target_26.getEnclosingFunction() = func)
}

predicate func_27(Function func) {
	exists(IfStmt target_27 |
		target_27.getCondition() instanceof RelationalOperation
		and target_27.getThen().(GotoStmt).toString() = "goto ..."
		and target_27.getThen().(GotoStmt).getName() ="fail"
		and (func.getEntryPoint().(BlockStmt).getStmt(37)=target_27 or func.getEntryPoint().(BlockStmt).getStmt(37).getFollowingStmt()=target_27))
}

predicate func_28(Function func) {
	exists(IfStmt target_28 |
		target_28.getCondition() instanceof RelationalOperation
		and target_28.getThen().(GotoStmt).toString() = "goto ..."
		and target_28.getThen().(GotoStmt).getName() ="fail"
		and (func.getEntryPoint().(BlockStmt).getStmt(38)=target_28 or func.getEntryPoint().(BlockStmt).getStmt(38).getFollowingStmt()=target_28))
}

predicate func_29(Function func) {
	exists(AssignExpr target_29 |
		target_29.getLValue().(VariableAccess).getType().hasName("SECURITY_STATUS")
		and target_29.getRValue() instanceof Literal
		and target_29.getEnclosingFunction() = func)
}

predicate func_30(Function func) {
	exists(LabelStmt target_30 |
		target_30.toString() = "label ...:"
		and target_30.getName() ="fail"
		and (func.getEntryPoint().(BlockStmt).getStmt(51)=target_30 or func.getEntryPoint().(BlockStmt).getStmt(51).getFollowingStmt()=target_30))
}

predicate func_32(Variable vs_370, Variable vmessage_375, BlockStmt target_101, RelationalOperation target_32) {
		 (target_32 instanceof GTExpr or target_32 instanceof LTExpr)
		and target_32.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_header")
		and target_32.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_32.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmessage_375
		and target_32.getGreaterOperand().(Literal).getValue()="0"
		and target_32.getParent().(IfStmt).getThen()=target_101
}

predicate func_33(Variable vs_370, RelationalOperation target_32, ExprStmt target_33) {
		target_33.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_33.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_33.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_33.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_32
}

predicate func_34(Variable vmessage_375, BlockStmt target_114, EqualityOperation target_34) {
		target_34.getAnOperand().(PointerFieldAccess).getTarget().getName()="MessageType"
		and target_34.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_34.getAnOperand().(Literal).getValue()="2"
		and target_34.getParent().(IfStmt).getThen()=target_114
}

predicate func_35(Variable vs_370, Variable vmessage_375, BlockStmt target_115, RelationalOperation target_35) {
		 (target_35 instanceof GTExpr or target_35 instanceof LTExpr)
		and target_35.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields")
		and target_35.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_35.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="TargetName"
		and target_35.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_35.getGreaterOperand().(Literal).getValue()="0"
		and target_35.getParent().(IfStmt).getThen()=target_115
}

predicate func_36(Variable vs_370, BlockStmt target_116, RelationalOperation target_36) {
		 (target_36 instanceof GTExpr or target_36 instanceof LTExpr)
		and target_36.getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_36.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_36.getGreaterOperand().(Literal).getValue()="4"
		and target_36.getParent().(IfStmt).getThen()=target_116
}

predicate func_37(Variable vs_370, BlockStmt target_117, RelationalOperation target_37) {
		 (target_37 instanceof GTExpr or target_37 instanceof LTExpr)
		and target_37.getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_37.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_37.getGreaterOperand().(Literal).getValue()="8"
		and target_37.getParent().(IfStmt).getThen()=target_117
}

predicate func_38(Variable vs_370, BlockStmt target_118, RelationalOperation target_38) {
		 (target_38 instanceof GTExpr or target_38 instanceof LTExpr)
		and target_38.getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_38.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_38.getGreaterOperand().(Literal).getValue()="8"
		and target_38.getParent().(IfStmt).getThen()=target_118
}

predicate func_39(Variable vs_370, Variable vmessage_375, BlockStmt target_119, RelationalOperation target_39) {
		 (target_39 instanceof GTExpr or target_39 instanceof LTExpr)
		and target_39.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields")
		and target_39.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_39.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="TargetInfo"
		and target_39.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_39.getGreaterOperand().(Literal).getValue()="0"
		and target_39.getParent().(IfStmt).getThen()=target_119
}

predicate func_40(Parameter vcontext_368, BlockStmt target_120, BitwiseAndExpr target_40) {
		target_40.getLeftOperand().(PointerFieldAccess).getTarget().getName()="NegotiateFlags"
		and target_40.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_40.getRightOperand().(Literal).getValue()="33554432"
		and target_40.getParent().(IfStmt).getThen()=target_120
}

predicate func_41(Variable vmessage_375, BlockStmt target_121, RelationalOperation target_41) {
		 (target_41 instanceof GTExpr or target_41 instanceof LTExpr)
		and target_41.getGreaterOperand().(ValueFieldAccess).getTarget().getName()="Len"
		and target_41.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="TargetName"
		and target_41.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_41.getLesserOperand().(Literal).getValue()="0"
		and target_41.getParent().(IfStmt).getThen()=target_121
}

predicate func_42(Variable vmessage_375, BlockStmt target_122, RelationalOperation target_42) {
		 (target_42 instanceof GTExpr or target_42 instanceof LTExpr)
		and target_42.getGreaterOperand().(ValueFieldAccess).getTarget().getName()="Len"
		and target_42.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="TargetInfo"
		and target_42.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_42.getLesserOperand().(Literal).getValue()="0"
		and target_42.getParent().(IfStmt).getThen()=target_122
}

predicate func_43(RelationalOperation target_42, Function func, DeclStmt target_43) {
		target_43.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_42
		and target_43.getEnclosingFunction() = func
}

predicate func_44(Variable vs_370, Variable vmessage_375, BlockStmt target_123, RelationalOperation target_44) {
		 (target_44 instanceof GTExpr or target_44 instanceof LTExpr)
		and target_44.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields_buffer")
		and target_44.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_44.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="TargetInfo"
		and target_44.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_44.getGreaterOperand().(Literal).getValue()="0"
		and target_44.getParent().(IfStmt).getThen()=target_123
}

predicate func_45(Parameter vcontext_368, Variable vmessage_375, RelationalOperation target_42, ExprStmt target_45) {
		target_45.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="pvBuffer"
		and target_45.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ChallengeTargetInfo"
		and target_45.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_45.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="Buffer"
		and target_45.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="TargetInfo"
		and target_45.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_45.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_42
}

predicate func_46(Parameter vcontext_368, Variable vmessage_375, RelationalOperation target_42, ExprStmt target_46) {
		target_46.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="cbBuffer"
		and target_46.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ChallengeTargetInfo"
		and target_46.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_46.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="Len"
		and target_46.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="TargetInfo"
		and target_46.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_46.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_42
}

predicate func_47(Variable vAvTimestamp_374, Variable vmessage_375, Variable vcbAvTimestamp_459, RelationalOperation target_42, ExprStmt target_47) {
		target_47.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vAvTimestamp_374
		and target_47.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ntlm_av_pair_get")
		and target_47.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="Buffer"
		and target_47.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="TargetInfo"
		and target_47.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_47.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="Len"
		and target_47.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="TargetInfo"
		and target_47.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_47.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcbAvTimestamp_459
		and target_47.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_42
}

predicate func_48(VariableAccess target_65, Function func, DeclStmt target_48) {
		target_48.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_65
		and target_48.getEnclosingFunction() = func
}

predicate func_49(Variable vptr_474, ReturnStmt target_124, NotExpr target_49) {
		target_49.getOperand().(VariableAccess).getTarget()=vptr_474
		and target_49.getParent().(IfStmt).getThen()=target_124
}

predicate func_50(Parameter vcontext_368, VariableAccess target_65, IfStmt target_50) {
		target_50.getCondition().(PointerFieldAccess).getTarget().getName()="NTLMv2"
		and target_50.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_50.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="UseMIC"
		and target_50.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_50.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_50.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_65
}

predicate func_51(Parameter vcontext_368, Variable vptr_474, VariableAccess target_65, ExprStmt target_51) {
		target_51.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_51.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ChallengeTimestamp"
		and target_51.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_51.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vptr_474
		and target_51.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_51.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_65
}

predicate func_52(Parameter vcontext_368, BlockStmt target_125, PointerFieldAccess target_52) {
		target_52.getTarget().getName()="NTLMv2"
		and target_52.getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_52.getParent().(IfStmt).getThen()=target_125
}

predicate func_53(Parameter vcontext_368, BlockStmt target_126, RelationalOperation target_53) {
		 (target_53 instanceof GTExpr or target_53 instanceof LTExpr)
		and target_53.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_construct_authenticate_target_info")
		and target_53.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontext_368
		and target_53.getGreaterOperand().(Literal).getValue()="0"
		and target_53.getParent().(IfStmt).getThen()=target_126
}

predicate func_54(Parameter vcontext_368, PointerFieldAccess target_52, ExprStmt target_54) {
		target_54.getExpr().(FunctionCall).getTarget().hasName("sspi_SecBufferFree")
		and target_54.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ChallengeTargetInfo"
		and target_54.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_54.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
}

predicate func_55(Parameter vcontext_368, PointerFieldAccess target_52, ExprStmt target_55) {
		target_55.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="pvBuffer"
		and target_55.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ChallengeTargetInfo"
		and target_55.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_55.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="pvBuffer"
		and target_55.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="AuthenticateTargetInfo"
		and target_55.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_55.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
}

predicate func_56(Parameter vcontext_368, PointerFieldAccess target_52, ExprStmt target_56) {
		target_56.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="cbBuffer"
		and target_56.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ChallengeTargetInfo"
		and target_56.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_56.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="cbBuffer"
		and target_56.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="AuthenticateTargetInfo"
		and target_56.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_56.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
}

predicate func_57(Parameter vcontext_368, BlockStmt target_127, RelationalOperation target_57) {
		 (target_57 instanceof GTExpr or target_57 instanceof LTExpr)
		and target_57.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_compute_lm_v2_response")
		and target_57.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontext_368
		and target_57.getGreaterOperand().(Literal).getValue()="0"
		and target_57.getParent().(IfStmt).getThen()=target_127
}

predicate func_58(Parameter vcontext_368, BlockStmt target_128, RelationalOperation target_58) {
		 (target_58 instanceof GTExpr or target_58 instanceof LTExpr)
		and target_58.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_compute_ntlm_v2_response")
		and target_58.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontext_368
		and target_58.getGreaterOperand().(Literal).getValue()="0"
		and target_58.getParent().(IfStmt).getThen()=target_128
}

predicate func_59(Variable vmessage_375, ValueFieldAccess target_59) {
		target_59.getTarget().getName()="Len"
		and target_59.getQualifier().(PointerFieldAccess).getTarget().getName()="TargetName"
		and target_59.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
}

predicate func_60(Variable vmessage_375, ValueFieldAccess target_60) {
		target_60.getTarget().getName()="Len"
		and target_60.getQualifier().(PointerFieldAccess).getTarget().getName()="TargetInfo"
		and target_60.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
}

predicate func_61(Parameter vcontext_368, Variable vlength_371, BlockStmt target_109, NotExpr target_61) {
		target_61.getOperand().(FunctionCall).getTarget().hasName("sspi_SecBufferAlloc")
		and target_61.getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ChallengeMessage"
		and target_61.getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_61.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlength_371
		and target_61.getParent().(IfStmt).getThen()=target_109
}

predicate func_63(Variable vs_370, VariableAccess target_63) {
		target_63.getTarget()=vs_370
		and target_63.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_64(Variable vs_370, VariableAccess target_64) {
		target_64.getTarget()=vs_370
		and target_64.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_65(Variable vAvTimestamp_374, BlockStmt target_129, VariableAccess target_65) {
		target_65.getTarget()=vAvTimestamp_374
		and target_65.getParent().(IfStmt).getThen()=target_129
}

predicate func_68(Variable vStartOffset_372, AssignExpr target_68) {
		target_68.getLValue().(VariableAccess).getTarget()=vStartOffset_372
		and target_68.getRValue() instanceof FunctionCall
}

predicate func_69(Variable vs_370, ExprStmt target_33, RelationalOperation target_35, FunctionCall target_69) {
		target_69.getTarget().hasName("Stream_Free")
		and target_69.getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_69.getArgument(1).(Literal).getValue()="0"
		and target_33.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_69.getArgument(0).(VariableAccess).getLocation())
		and target_69.getArgument(0).(VariableAccess).getLocation().isBefore(target_35.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_70(EqualityOperation target_34, Function func, ReturnStmt target_70) {
		target_70.getExpr().(Literal).getValue()="2148074248"
		and target_70.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_34
		and target_70.getEnclosingFunction() = func
}

predicate func_71(Variable vs_370, RelationalOperation target_35, RelationalOperation target_36, ExprStmt target_71) {
		target_71.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_71.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_71.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_71.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_35
		and target_71.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_36.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_72(RelationalOperation target_35, Function func, ReturnStmt target_72) {
		target_72.getExpr().(Literal).getValue()="2148074248"
		and target_72.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_35
		and target_72.getEnclosingFunction() = func
}

predicate func_73(Variable vs_370, RelationalOperation target_36, ExprStmt target_73) {
		target_73.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_73.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_73.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_73.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_36
}

predicate func_74(RelationalOperation target_36, Function func, ReturnStmt target_74) {
		target_74.getExpr().(Literal).getValue()="2148074248"
		and target_74.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_36
		and target_74.getEnclosingFunction() = func
}

predicate func_75(Variable vs_370, RelationalOperation target_37, ExprStmt target_131, ExprStmt target_75) {
		target_75.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_75.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_75.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_75.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_37
		and target_75.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_131.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_76(RelationalOperation target_37, Function func, ReturnStmt target_76) {
		target_76.getExpr().(Literal).getValue()="2148074248"
		and target_76.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_37
		and target_76.getEnclosingFunction() = func
}

predicate func_77(Variable vs_370, RelationalOperation target_38, ExprStmt target_132, ExprStmt target_77) {
		target_77.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_77.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_77.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_77.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_38
		and target_77.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_132.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_78(RelationalOperation target_38, Function func, ReturnStmt target_78) {
		target_78.getExpr().(Literal).getValue()="2148074248"
		and target_78.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_38
		and target_78.getEnclosingFunction() = func
}

predicate func_79(Variable vs_370, RelationalOperation target_39, RelationalOperation target_105, ExprStmt target_79) {
		target_79.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_79.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_79.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_79.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
		and target_79.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_105.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_80(RelationalOperation target_39, Function func, ReturnStmt target_80) {
		target_80.getExpr().(Literal).getValue()="2148074248"
		and target_80.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
		and target_80.getEnclosingFunction() = func
}

predicate func_81(Variable vs_370, RelationalOperation target_105, ExprStmt target_81) {
		target_81.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_81.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_81.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_81.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_105
}

predicate func_82(RelationalOperation target_105, Function func, ReturnStmt target_82) {
		target_82.getExpr().(Literal).getValue()="2148074248"
		and target_82.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_105
		and target_82.getEnclosingFunction() = func
}

predicate func_83(Variable vs_370, Variable vPayloadOffset_373, AssignExpr target_83) {
		target_83.getLValue().(VariableAccess).getTarget()=vPayloadOffset_373
		and target_83.getRValue().(FunctionCall).getTarget().hasName("Stream_Pointer")
		and target_83.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
}

predicate func_84(Variable vs_370, RelationalOperation target_106, RelationalOperation target_44, ExprStmt target_84) {
		target_84.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_84.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_84.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_84.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_106
		and target_84.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_44.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_85(RelationalOperation target_106, Function func, ReturnStmt target_85) {
		target_85.getExpr() instanceof Literal
		and target_85.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_106
		and target_85.getEnclosingFunction() = func
}

predicate func_86(Variable vs_370, RelationalOperation target_44, ExprStmt target_89, ExprStmt target_86) {
		target_86.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_86.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_86.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_86.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
		and target_86.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_89.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_87(RelationalOperation target_44, Function func, ReturnStmt target_87) {
		target_87.getExpr().(Literal).getValue()="2148074244"
		and target_87.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
		and target_87.getEnclosingFunction() = func
}

predicate func_88(Variable vlength_371, Variable vStartOffset_372, Variable vPayloadOffset_373, AssignExpr target_88) {
		target_88.getLValue().(VariableAccess).getTarget()=vlength_371
		and target_88.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vPayloadOffset_373
		and target_88.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vStartOffset_372
		and target_88.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand() instanceof ValueFieldAccess
		and target_88.getRValue().(AddExpr).getAnOperand() instanceof ValueFieldAccess
}

predicate func_89(Variable vs_370, NotExpr target_61, ExprStmt target_86, ExprStmt target_93, ExprStmt target_89) {
		target_89.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_89.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_89.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_89.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_61
		and target_86.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_89.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_89.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_93.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_90(NotExpr target_61, Function func, ReturnStmt target_90) {
		target_90.getExpr().(Literal).getValue()="2148074244"
		and target_90.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_61
		and target_90.getEnclosingFunction() = func
}

/*predicate func_91(Parameter vcontext_368, Variable vlength_371, Variable vStartOffset_372, AddressOfExpr target_134, IfStmt target_135, VariableAccess target_91) {
		target_91.getTarget()=vStartOffset_372
		and target_91.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_91.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="pvBuffer"
		and target_91.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ChallengeMessage"
		and target_91.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_91.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlength_371
		and target_134.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_91.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_91.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_135.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
/*predicate func_92(Parameter vcontext_368, Variable vlength_371, Variable vStartOffset_372, AddressOfExpr target_134, IfStmt target_135, VariableAccess target_92) {
		target_92.getTarget()=vlength_371
		and target_92.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_92.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="pvBuffer"
		and target_92.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ChallengeMessage"
		and target_92.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_92.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vStartOffset_372
		and target_134.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_92.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_92.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_135.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_93(Variable vs_370, RelationalOperation target_53, ExprStmt target_89, ExprStmt target_95, ExprStmt target_93) {
		target_93.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_93.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_93.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_93.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_53
		and target_89.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_93.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_93.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_95.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_94(RelationalOperation target_53, Function func, ReturnStmt target_94) {
		target_94.getExpr().(Literal).getValue()="2148074244"
		and target_94.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_53
		and target_94.getEnclosingFunction() = func
}

predicate func_95(Variable vs_370, RelationalOperation target_57, ExprStmt target_93, ExprStmt target_97, ExprStmt target_95) {
		target_95.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_95.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_95.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_95.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_57
		and target_93.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_95.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_95.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_97.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_96(RelationalOperation target_57, Function func, ReturnStmt target_96) {
		target_96.getExpr().(Literal).getValue()="2148074244"
		and target_96.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_57
		and target_96.getEnclosingFunction() = func
}

predicate func_97(Variable vs_370, RelationalOperation target_58, ExprStmt target_95, ExprStmt target_97) {
		target_97.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_97.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_97.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_97.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_58
		and target_95.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_97.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_98(RelationalOperation target_58, Function func, ReturnStmt target_98) {
		target_98.getExpr().(Literal).getValue()="2148074244"
		and target_98.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_58
		and target_98.getEnclosingFunction() = func
}

predicate func_99(Variable vs_370, ExprStmt target_97, FunctionCall target_99) {
		target_99.getTarget().hasName("Stream_Free")
		and target_99.getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_99.getArgument(1).(Literal).getValue()="0"
		and target_97.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_99.getArgument(0).(VariableAccess).getLocation())
}

predicate func_100(Function func, ReturnStmt target_100) {
		target_100.getExpr() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_100
}

predicate func_101(BlockStmt target_101) {
		target_101.getStmt(0) instanceof ExprStmt
		and target_101.getStmt(1).(ReturnStmt).getExpr() instanceof Literal
}

predicate func_102(Parameter vcontext_368, Variable vmessage_375, ExprStmt target_102) {
		target_102.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmessage_375
		and target_102.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="CHALLENGE_MESSAGE"
		and target_102.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
}

predicate func_103(Parameter vcontext_368, Variable vmessage_375, ExprStmt target_103) {
		target_103.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="NegotiateFlags"
		and target_103.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_103.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="NegotiateFlags"
		and target_103.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
}

predicate func_104(Parameter vbuffer_368, Variable vs_370, ExprStmt target_104) {
		target_104.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_370
		and target_104.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Stream_New")
		and target_104.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pvBuffer"
		and target_104.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuffer_368
		and target_104.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="cbBuffer"
		and target_104.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuffer_368
}

predicate func_105(Variable vs_370, Variable vmessage_375, RelationalOperation target_105) {
		 (target_105 instanceof GTExpr or target_105 instanceof LTExpr)
		and target_105.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_version_info")
		and target_105.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_105.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="Version"
		and target_105.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_105.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_106(Variable vs_370, Variable vmessage_375, RelationalOperation target_106) {
		 (target_106 instanceof GTExpr or target_106 instanceof LTExpr)
		and target_106.getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields_buffer")
		and target_106.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_106.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="TargetName"
		and target_106.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_106.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_109(BlockStmt target_109) {
		target_109.getStmt(0) instanceof ExprStmt
		and target_109.getStmt(1) instanceof ReturnStmt
}

predicate func_111(Parameter vcontext_368, ExprStmt target_111) {
		target_111.getExpr().(FunctionCall).getTarget().hasName("ntlm_generate_timestamp")
		and target_111.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontext_368
}

predicate func_112(Variable vs_370, NotExpr target_112) {
		target_112.getOperand().(VariableAccess).getTarget()=vs_370
}

predicate func_113(Parameter vcontext_368, Variable vlength_371, Variable vStartOffset_372, ExprStmt target_113) {
		target_113.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_113.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="pvBuffer"
		and target_113.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ChallengeMessage"
		and target_113.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_113.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vStartOffset_372
		and target_113.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlength_371
}

predicate func_114(BlockStmt target_114) {
		target_114.getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_114.getStmt(1) instanceof ReturnStmt
}

predicate func_115(BlockStmt target_115) {
		target_115.getStmt(0) instanceof ExprStmt
		and target_115.getStmt(1) instanceof ReturnStmt
}

predicate func_116(BlockStmt target_116) {
		target_116.getStmt(0) instanceof ExprStmt
		and target_116.getStmt(1) instanceof ReturnStmt
}

predicate func_117(BlockStmt target_117) {
		target_117.getStmt(0) instanceof ExprStmt
		and target_117.getStmt(1) instanceof ReturnStmt
}

predicate func_118(BlockStmt target_118) {
		target_118.getStmt(0) instanceof ExprStmt
		and target_118.getStmt(1) instanceof ReturnStmt
}

predicate func_119(BlockStmt target_119) {
		target_119.getStmt(0) instanceof ExprStmt
		and target_119.getStmt(1) instanceof ReturnStmt
}

predicate func_120(Variable vs_370, Variable vmessage_375, BlockStmt target_120) {
		target_120.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_version_info")
		and target_120.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_120.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="Version"
		and target_120.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_120.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_120.getStmt(0).(IfStmt).getThen() instanceof BlockStmt
}

predicate func_121(Variable vs_370, Variable vmessage_375, BlockStmt target_121) {
		target_121.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("ntlm_read_message_fields_buffer")
		and target_121.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_121.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="TargetName"
		and target_121.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_121.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_121.getStmt(0).(IfStmt).getThen() instanceof BlockStmt
}

predicate func_122(BlockStmt target_122) {
		target_122.getStmt(1).(IfStmt).getCondition() instanceof RelationalOperation
		and target_122.getStmt(1).(IfStmt).getThen() instanceof BlockStmt
		and target_122.getStmt(2) instanceof ExprStmt
		and target_122.getStmt(3) instanceof ExprStmt
		and target_122.getStmt(4) instanceof ExprStmt
}

predicate func_123(BlockStmt target_123) {
		target_123.getStmt(0) instanceof ExprStmt
		and target_123.getStmt(1) instanceof ReturnStmt
}

predicate func_124(ReturnStmt target_124) {
		target_124.getExpr().(Literal).getValue()="2148074244"
}

predicate func_125(BlockStmt target_125) {
		target_125.getStmt(0).(IfStmt).getCondition() instanceof RelationalOperation
		and target_125.getStmt(0).(IfStmt).getThen() instanceof BlockStmt
		and target_125.getStmt(1) instanceof ExprStmt
		and target_125.getStmt(2) instanceof ExprStmt
		and target_125.getStmt(3) instanceof ExprStmt
}

predicate func_126(BlockStmt target_126) {
		target_126.getStmt(0) instanceof ExprStmt
		and target_126.getStmt(1) instanceof ReturnStmt
}

predicate func_127(BlockStmt target_127) {
		target_127.getStmt(0) instanceof ExprStmt
		and target_127.getStmt(1) instanceof ReturnStmt
}

predicate func_128(BlockStmt target_128) {
		target_128.getStmt(0) instanceof ExprStmt
		and target_128.getStmt(1) instanceof ReturnStmt
}

predicate func_129(BlockStmt target_129) {
		target_129.getStmt(1).(IfStmt).getCondition() instanceof NotExpr
		and target_129.getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="2148074244"
		and target_129.getStmt(2) instanceof IfStmt
		and target_129.getStmt(3) instanceof ExprStmt
}

predicate func_131(Variable vs_370, Variable vmessage_375, ExprStmt target_131) {
		target_131.getExpr().(FunctionCall).getTarget().hasName("Stream_Read")
		and target_131.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_131.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="ServerChallenge"
		and target_131.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_131.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="8"
}

predicate func_132(Variable vs_370, Variable vmessage_375, ExprStmt target_132) {
		target_132.getExpr().(FunctionCall).getTarget().hasName("Stream_Read")
		and target_132.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_370
		and target_132.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="Reserved"
		and target_132.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_375
		and target_132.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="8"
}

predicate func_134(Parameter vcontext_368, AddressOfExpr target_134) {
		target_134.getOperand().(PointerFieldAccess).getTarget().getName()="ChallengeMessage"
		and target_134.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
}

predicate func_135(Parameter vcontext_368, IfStmt target_135) {
		target_135.getCondition().(PointerFieldAccess).getTarget().getName()="NTLMv2"
		and target_135.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_368
		and target_135.getThen() instanceof BlockStmt
}

from Function func, Parameter vcontext_368, Parameter vbuffer_368, Variable vs_370, Variable vlength_371, Variable vStartOffset_372, Variable vPayloadOffset_373, Variable vAvTimestamp_374, Variable vmessage_375, Variable vcbAvTimestamp_459, Variable vptr_474, FunctionCall target_0, RelationalOperation target_32, ExprStmt target_33, EqualityOperation target_34, RelationalOperation target_35, RelationalOperation target_36, RelationalOperation target_37, RelationalOperation target_38, RelationalOperation target_39, BitwiseAndExpr target_40, RelationalOperation target_41, RelationalOperation target_42, DeclStmt target_43, RelationalOperation target_44, ExprStmt target_45, ExprStmt target_46, ExprStmt target_47, DeclStmt target_48, NotExpr target_49, IfStmt target_50, ExprStmt target_51, PointerFieldAccess target_52, RelationalOperation target_53, ExprStmt target_54, ExprStmt target_55, ExprStmt target_56, RelationalOperation target_57, RelationalOperation target_58, ValueFieldAccess target_59, ValueFieldAccess target_60, NotExpr target_61, VariableAccess target_63, VariableAccess target_64, VariableAccess target_65, AssignExpr target_68, FunctionCall target_69, ReturnStmt target_70, ExprStmt target_71, ReturnStmt target_72, ExprStmt target_73, ReturnStmt target_74, ExprStmt target_75, ReturnStmt target_76, ExprStmt target_77, ReturnStmt target_78, ExprStmt target_79, ReturnStmt target_80, ExprStmt target_81, ReturnStmt target_82, AssignExpr target_83, ExprStmt target_84, ReturnStmt target_85, ExprStmt target_86, ReturnStmt target_87, AssignExpr target_88, ExprStmt target_89, ReturnStmt target_90, ExprStmt target_93, ReturnStmt target_94, ExprStmt target_95, ReturnStmt target_96, ExprStmt target_97, ReturnStmt target_98, FunctionCall target_99, ReturnStmt target_100, BlockStmt target_101, ExprStmt target_102, ExprStmt target_103, ExprStmt target_104, RelationalOperation target_105, RelationalOperation target_106, BlockStmt target_109, ExprStmt target_111, NotExpr target_112, ExprStmt target_113, BlockStmt target_114, BlockStmt target_115, BlockStmt target_116, BlockStmt target_117, BlockStmt target_118, BlockStmt target_119, BlockStmt target_120, BlockStmt target_121, BlockStmt target_122, BlockStmt target_123, ReturnStmt target_124, BlockStmt target_125, BlockStmt target_126, BlockStmt target_127, BlockStmt target_128, BlockStmt target_129, ExprStmt target_131, ExprStmt target_132, AddressOfExpr target_134, IfStmt target_135
where
func_0(vs_370, target_0)
and not func_4(vcontext_368, vbuffer_368, target_101, target_102, target_103, target_104)
and not func_5(vs_370, vStartOffset_372, target_33, target_35)
and not func_6(target_34, func)
and not func_7(target_35, func)
and not func_8(target_36, func)
and not func_9(target_37, func)
and not func_10(target_38, func)
and not func_11(target_39, func)
and not func_12(target_40, func)
and not func_13(target_105, func)
and not func_14(vs_370, vPayloadOffset_373, target_35, target_36)
and not func_15(func)
and not func_16(target_106, func)
and not func_17(target_65, func)
and not func_18(target_53, func)
and not func_19(vlength_371, vStartOffset_372, vPayloadOffset_373, target_61)
and not func_20(vbuffer_368, vlength_371, target_109, target_61)
and not func_21(target_61, func)
and not func_22(target_52, func)
and not func_23(vcontext_368, target_111, target_57)
and not func_24(vcontext_368, vs_370, vlength_371, vStartOffset_372, target_112, target_32, target_113)
and not func_26(target_37, func)
and not func_27(func)
and not func_28(func)
and not func_29(func)
and not func_30(func)
and func_32(vs_370, vmessage_375, target_101, target_32)
and func_33(vs_370, target_32, target_33)
and func_34(vmessage_375, target_114, target_34)
and func_35(vs_370, vmessage_375, target_115, target_35)
and func_36(vs_370, target_116, target_36)
and func_37(vs_370, target_117, target_37)
and func_38(vs_370, target_118, target_38)
and func_39(vs_370, vmessage_375, target_119, target_39)
and func_40(vcontext_368, target_120, target_40)
and func_41(vmessage_375, target_121, target_41)
and func_42(vmessage_375, target_122, target_42)
and func_43(target_42, func, target_43)
and func_44(vs_370, vmessage_375, target_123, target_44)
and func_45(vcontext_368, vmessage_375, target_42, target_45)
and func_46(vcontext_368, vmessage_375, target_42, target_46)
and func_47(vAvTimestamp_374, vmessage_375, vcbAvTimestamp_459, target_42, target_47)
and func_48(target_65, func, target_48)
and func_49(vptr_474, target_124, target_49)
and func_50(vcontext_368, target_65, target_50)
and func_51(vcontext_368, vptr_474, target_65, target_51)
and func_52(vcontext_368, target_125, target_52)
and func_53(vcontext_368, target_126, target_53)
and func_54(vcontext_368, target_52, target_54)
and func_55(vcontext_368, target_52, target_55)
and func_56(vcontext_368, target_52, target_56)
and func_57(vcontext_368, target_127, target_57)
and func_58(vcontext_368, target_128, target_58)
and func_59(vmessage_375, target_59)
and func_60(vmessage_375, target_60)
and func_61(vcontext_368, vlength_371, target_109, target_61)
and func_63(vs_370, target_63)
and func_64(vs_370, target_64)
and func_65(vAvTimestamp_374, target_129, target_65)
and func_68(vStartOffset_372, target_68)
and func_69(vs_370, target_33, target_35, target_69)
and func_70(target_34, func, target_70)
and func_71(vs_370, target_35, target_36, target_71)
and func_72(target_35, func, target_72)
and func_73(vs_370, target_36, target_73)
and func_74(target_36, func, target_74)
and func_75(vs_370, target_37, target_131, target_75)
and func_76(target_37, func, target_76)
and func_77(vs_370, target_38, target_132, target_77)
and func_78(target_38, func, target_78)
and func_79(vs_370, target_39, target_105, target_79)
and func_80(target_39, func, target_80)
and func_81(vs_370, target_105, target_81)
and func_82(target_105, func, target_82)
and func_83(vs_370, vPayloadOffset_373, target_83)
and func_84(vs_370, target_106, target_44, target_84)
and func_85(target_106, func, target_85)
and func_86(vs_370, target_44, target_89, target_86)
and func_87(target_44, func, target_87)
and func_88(vlength_371, vStartOffset_372, vPayloadOffset_373, target_88)
and func_89(vs_370, target_61, target_86, target_93, target_89)
and func_90(target_61, func, target_90)
and func_93(vs_370, target_53, target_89, target_95, target_93)
and func_94(target_53, func, target_94)
and func_95(vs_370, target_57, target_93, target_97, target_95)
and func_96(target_57, func, target_96)
and func_97(vs_370, target_58, target_95, target_97)
and func_98(target_58, func, target_98)
and func_99(vs_370, target_97, target_99)
and func_100(func, target_100)
and func_101(target_101)
and func_102(vcontext_368, vmessage_375, target_102)
and func_103(vcontext_368, vmessage_375, target_103)
and func_104(vbuffer_368, vs_370, target_104)
and func_105(vs_370, vmessage_375, target_105)
and func_106(vs_370, vmessage_375, target_106)
and func_109(target_109)
and func_111(vcontext_368, target_111)
and func_112(vs_370, target_112)
and func_113(vcontext_368, vlength_371, vStartOffset_372, target_113)
and func_114(target_114)
and func_115(target_115)
and func_116(target_116)
and func_117(target_117)
and func_118(target_118)
and func_119(target_119)
and func_120(vs_370, vmessage_375, target_120)
and func_121(vs_370, vmessage_375, target_121)
and func_122(target_122)
and func_123(target_123)
and func_124(target_124)
and func_125(target_125)
and func_126(target_126)
and func_127(target_127)
and func_128(target_128)
and func_129(target_129)
and func_131(vs_370, vmessage_375, target_131)
and func_132(vs_370, vmessage_375, target_132)
and func_134(vcontext_368, target_134)
and func_135(vcontext_368, target_135)
and vcontext_368.getType().hasName("NTLM_CONTEXT *")
and vbuffer_368.getType().hasName("PSecBuffer")
and vs_370.getType().hasName("wStream *")
and vlength_371.getType().hasName("int")
and vStartOffset_372.getType().hasName("PBYTE")
and vPayloadOffset_373.getType().hasName("PBYTE")
and vAvTimestamp_374.getType().hasName("NTLM_AV_PAIR *")
and vmessage_375.getType().hasName("NTLM_CHALLENGE_MESSAGE *")
and vcbAvTimestamp_459.getType().hasName("size_t")
and vptr_474.getType().hasName("PBYTE")
and vcontext_368.getParentScope+() = func
and vbuffer_368.getParentScope+() = func
and vs_370.getParentScope+() = func
and vlength_371.getParentScope+() = func
and vStartOffset_372.getParentScope+() = func
and vPayloadOffset_373.getParentScope+() = func
and vAvTimestamp_374.getParentScope+() = func
and vmessage_375.getParentScope+() = func
and vcbAvTimestamp_459.getParentScope+() = func
and vptr_474.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
