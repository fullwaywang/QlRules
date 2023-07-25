/**
 * @name curl-facb0e4662415b5f28163e853dc6742ac5fafb3d-tftp_connect
 * @id cpp/curl/facb0e4662415b5f28163e853dc6742ac5fafb3d/tftp-connect
 * @description curl-facb0e4662415b5f28163e853dc6742ac5fafb3d-lib/tftp.c-tftp_connect CVE-2019-5482
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vblksize_987, VariableAccess target_0) {
		target_0.getTarget()=vblksize_987
}

predicate func_1(Variable vblksize_987, VariableAccess target_1) {
		target_1.getTarget()=vblksize_987
}

predicate func_3(Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="512"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="512"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_3))
}

predicate func_4(Variable vstate_986, ExprStmt target_6, ExprStmt target_7, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="blksize"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_986
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="512"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_4)
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Variable vstate_986, Variable vblksize_987, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="blksize"
		and target_5.getQualifier().(VariableAccess).getTarget()=vstate_986
		and target_5.getParent().(AssignExpr).getLValue() = target_5
		and target_5.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=vblksize_987
}

predicate func_6(Variable vstate_986, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="error"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_986
}

predicate func_7(Variable vstate_986, Variable vblksize_987, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="requested_blksize"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_986
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vblksize_987
}

from Function func, Variable vstate_986, Variable vblksize_987, VariableAccess target_0, VariableAccess target_1, PointerFieldAccess target_5, ExprStmt target_6, ExprStmt target_7
where
func_0(vblksize_987, target_0)
and func_1(vblksize_987, target_1)
and not func_3(func)
and not func_4(vstate_986, target_6, target_7, func)
and func_5(vstate_986, vblksize_987, target_5)
and func_6(vstate_986, target_6)
and func_7(vstate_986, vblksize_987, target_7)
and vstate_986.getType().hasName("tftp_state_data_t *")
and vblksize_987.getType().hasName("int")
and vstate_986.getParentScope+() = func
and vblksize_987.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
