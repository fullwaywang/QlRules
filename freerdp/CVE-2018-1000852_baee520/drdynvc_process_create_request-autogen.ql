/**
 * @name freerdp-baee520e3dd9be6511c45a14c5f5e77784de1471-drdynvc_process_create_request
 * @id cpp/freerdp/baee520e3dd9be6511c45a14c5f5e77784de1471/drdynvc-process-create-request
 * @description freerdp-baee520e3dd9be6511c45a14c5f5e77784de1471-channels/drdynvc/client/drdynvc_main.c-drdynvc_process_create_request CVE-2018-1000852
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcbChId_931, Parameter vs_931, ExprStmt target_10, ExprStmt target_11, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_931
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("drdynvc_cblen_to_bytes")
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcbChId_931
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="13"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Function func) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("char *")
		and target_1.getRValue() instanceof FunctionCall
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vs_931, FunctionCall target_7, FunctionCall target_9, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_931
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_2)
		and target_7.getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_9.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("strnlen")
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("size_t")
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("size_t")
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="13"
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_3))
}

predicate func_5(Parameter vdrdynvc_930, Variable vChannelId_935, Variable vchannel_status_937, ExprStmt target_12, LogicalAndExpr target_13, AssignExpr target_14, EqualityOperation target_15, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchannel_status_937
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dvcman_create_channel")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdrdynvc_930
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="channel_mgr"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdrdynvc_930
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vChannelId_935
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("char *")
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_5)
		and target_12.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_14.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_15.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vs_931, FunctionCall target_7) {
		target_7.getTarget().hasName("Stream_Pointer")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vs_931
}

predicate func_8(Parameter vs_931, VariableAccess target_8) {
		target_8.getTarget()=vs_931
		and target_8.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(3) instanceof FunctionCall
}

predicate func_9(Parameter vs_931, ExprStmt target_11, FunctionCall target_9) {
		target_9.getTarget().hasName("Stream_Pointer")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vs_931
		and target_9.getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_10(Parameter vcbChId_931, Parameter vs_931, Variable vChannelId_935, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vChannelId_935
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("drdynvc_read_variable_uint")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_931
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcbChId_931
}

predicate func_11(Parameter vs_931, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("Stream_SetPosition")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_931
		and target_11.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
}

predicate func_12(Parameter vdrdynvc_930, Variable vChannelId_935, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("WLog_PrintMessage")
		and target_12.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_12.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdrdynvc_930
		and target_12.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_12.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_12.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_12.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_12.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="process_create_request: ChannelId=%u ChannelName=%s"
		and target_12.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vChannelId_935
		and target_12.getExpr().(FunctionCall).getArgument(8) instanceof FunctionCall
}

predicate func_13(Parameter vdrdynvc_930, LogicalAndExpr target_13) {
		target_13.getAnOperand().(PointerFieldAccess).getTarget().getName()="log"
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdrdynvc_930
		and target_13.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_13.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("WLog_GetLogLevel")
		and target_13.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_13.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdrdynvc_930
}

predicate func_14(Parameter vdrdynvc_930, Variable vChannelId_935, AssignExpr target_14) {
		target_14.getRValue().(FunctionCall).getTarget().hasName("dvcman_open_channel")
		and target_14.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdrdynvc_930
		and target_14.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="channel_mgr"
		and target_14.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdrdynvc_930
		and target_14.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vChannelId_935
}

predicate func_15(Variable vchannel_status_937, EqualityOperation target_15) {
		target_15.getAnOperand().(VariableAccess).getTarget()=vchannel_status_937
		and target_15.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vdrdynvc_930, Parameter vcbChId_931, Parameter vs_931, Variable vChannelId_935, Variable vchannel_status_937, FunctionCall target_7, VariableAccess target_8, FunctionCall target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, LogicalAndExpr target_13, AssignExpr target_14, EqualityOperation target_15
where
not func_0(vcbChId_931, vs_931, target_10, target_11, func)
and not func_1(func)
and not func_2(vs_931, target_7, target_9, func)
and not func_3(func)
and not func_5(vdrdynvc_930, vChannelId_935, vchannel_status_937, target_12, target_13, target_14, target_15, func)
and func_7(vs_931, target_7)
and func_8(vs_931, target_8)
and func_9(vs_931, target_11, target_9)
and func_10(vcbChId_931, vs_931, vChannelId_935, target_10)
and func_11(vs_931, target_11)
and func_12(vdrdynvc_930, vChannelId_935, target_12)
and func_13(vdrdynvc_930, target_13)
and func_14(vdrdynvc_930, vChannelId_935, target_14)
and func_15(vchannel_status_937, target_15)
and vdrdynvc_930.getType().hasName("drdynvcPlugin *")
and vcbChId_931.getType().hasName("int")
and vs_931.getType().hasName("wStream *")
and vChannelId_935.getType().hasName("UINT32")
and vchannel_status_937.getType().hasName("UINT")
and vdrdynvc_930.getParentScope+() = func
and vcbChId_931.getParentScope+() = func
and vs_931.getParentScope+() = func
and vChannelId_935.getParentScope+() = func
and vchannel_status_937.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
