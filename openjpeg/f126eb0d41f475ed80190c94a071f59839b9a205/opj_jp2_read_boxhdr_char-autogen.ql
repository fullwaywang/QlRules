/**
 * @name openjpeg-f126eb0d41f475ed80190c94a071f59839b9a205-opj_jp2_read_boxhdr_char
 * @id cpp/openjpeg/f126eb0d41f475ed80190c94a071f59839b9a205/opj-jp2-read-boxhdr-char
 * @description openjpeg-f126eb0d41f475ed80190c94a071f59839b9a205-src/lib/openjp2/jp2.c-opj_jp2_read_boxhdr_char CVE-2014-7945
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbox_2222, Parameter vp_number_bytes_read_2224, Parameter vp_manager_2226, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbox_2222
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_number_bytes_read_2224
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_2226
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Box length is inconsistent.\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_0)
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vbox_2222, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbox_2222
		and target_1.getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Parameter vp_number_bytes_read_2224, ExprStmt target_2) {
		target_2.getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_number_bytes_read_2224
		and target_2.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="4"
}

predicate func_3(Parameter vp_manager_2226, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_2226
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Cannot handle box of undefined sizes\n"
}

from Function func, Parameter vbox_2222, Parameter vp_number_bytes_read_2224, Parameter vp_manager_2226, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vbox_2222, vp_number_bytes_read_2224, vp_manager_2226, target_1, target_2, target_3, func)
and func_1(vbox_2222, target_1)
and func_2(vp_number_bytes_read_2224, target_2)
and func_3(vp_manager_2226, target_3)
and vbox_2222.getType().hasName("opj_jp2_box_t *")
and vp_number_bytes_read_2224.getType().hasName("OPJ_UINT32 *")
and vp_manager_2226.getType().hasName("opj_event_mgr_t *")
and vbox_2222.getParentScope+() = func
and vp_number_bytes_read_2224.getParentScope+() = func
and vp_manager_2226.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
