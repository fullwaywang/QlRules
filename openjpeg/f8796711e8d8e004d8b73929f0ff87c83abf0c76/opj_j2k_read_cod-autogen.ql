/**
 * @name openjpeg-f8796711e8d8e004d8b73929f0ff87c83abf0c76-opj_j2k_read_cod
 * @id cpp/openjpeg/f8796711e8d8e004d8b73929f0ff87c83abf0c76/opj-j2k-read-cod
 * @description openjpeg-f8796711e8d8e004d8b73929f0ff87c83abf0c76-src/lib/openjp2/j2k.c-opj_j2k_read_cod CVE-2014-7945
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_manager_2387, Variable vl_tcp_2394, ExprStmt target_1, NotExpr target_2, ExprStmt target_3, AddressOfExpr target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="prg"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_2394
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_2387
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unknown progression order in COD marker\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="prg"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_2394
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getOperand().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_manager_2387, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_2387
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unknown Scod value in COD marker\n"
}

predicate func_2(Parameter vp_manager_2387, NotExpr target_2) {
		target_2.getOperand().(FunctionCall).getTarget().hasName("opj_j2k_read_SPCod_SPCoc")
		and target_2.getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vp_manager_2387
}

predicate func_3(Variable vl_tcp_2394, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="prg"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_2394
}

predicate func_4(Variable vl_tcp_2394, AddressOfExpr target_4) {
		target_4.getOperand().(PointerFieldAccess).getTarget().getName()="numlayers"
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_2394
}

from Function func, Parameter vp_manager_2387, Variable vl_tcp_2394, ExprStmt target_1, NotExpr target_2, ExprStmt target_3, AddressOfExpr target_4
where
not func_0(vp_manager_2387, vl_tcp_2394, target_1, target_2, target_3, target_4, func)
and func_1(vp_manager_2387, target_1)
and func_2(vp_manager_2387, target_2)
and func_3(vl_tcp_2394, target_3)
and func_4(vl_tcp_2394, target_4)
and vp_manager_2387.getType().hasName("opj_event_mgr_t *")
and vl_tcp_2394.getType().hasName("opj_tcp_t *")
and vp_manager_2387.getParentScope+() = func
and vl_tcp_2394.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
