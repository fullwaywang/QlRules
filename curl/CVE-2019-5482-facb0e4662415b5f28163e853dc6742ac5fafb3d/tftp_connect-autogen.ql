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
		and target_0.getParent().(AddExpr).getParent().(AddExpr).getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget().getType().hasName("curl_calloc_callback")
		and target_0.getParent().(AddExpr).getParent().(AddExpr).getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(0).(Literal).getValue()="1"
		and target_0.getParent().(AddExpr).getParent().(AddExpr).getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(1).(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_0.getParent().(AddExpr).getParent().(AddExpr).getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="2"
}

predicate func_1(Variable vblksize_987, VariableAccess target_1) {
		target_1.getTarget()=vblksize_987
		and target_1.getParent().(AddExpr).getParent().(AddExpr).getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget().getType().hasName("curl_calloc_callback")
		and target_1.getParent().(AddExpr).getParent().(AddExpr).getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(0).(Literal).getValue()="1"
		and target_1.getParent().(AddExpr).getParent().(AddExpr).getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(1).(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_1.getParent().(AddExpr).getParent().(AddExpr).getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="2"
}

predicate func_2(Variable vblksize_987, AddExpr target_7, ExprStmt target_8, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vblksize_987
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_2)
		and target_7.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_4(Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="512"
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="512"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_4))
}

predicate func_5(Variable vstate_986, ExprStmt target_9, ExprStmt target_8) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(PointerFieldAccess).getTarget().getName()="blksize"
		and target_5.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_986
		and target_5.getRValue().(Literal).getValue()="512"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Variable vstate_986, Variable vblksize_987, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="blksize"
		and target_6.getQualifier().(VariableAccess).getTarget()=vstate_986
		and target_6.getParent().(AssignExpr).getLValue() = target_6
		and target_6.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=vblksize_987
}

predicate func_7(Variable vblksize_987, AddExpr target_7) {
		target_7.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vblksize_987
		and target_7.getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_7.getAnOperand().(Literal).getValue()="2"
}

predicate func_8(Variable vstate_986, Variable vblksize_987, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="requested_blksize"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_986
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vblksize_987
}

predicate func_9(Variable vstate_986, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="error"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_986
}

from Function func, Variable vstate_986, Variable vblksize_987, VariableAccess target_0, VariableAccess target_1, PointerFieldAccess target_6, AddExpr target_7, ExprStmt target_8, ExprStmt target_9
where
func_0(vblksize_987, target_0)
and func_1(vblksize_987, target_1)
and not func_2(vblksize_987, target_7, target_8, func)
and not func_4(func)
and not func_5(vstate_986, target_9, target_8)
and func_6(vstate_986, vblksize_987, target_6)
and func_7(vblksize_987, target_7)
and func_8(vstate_986, vblksize_987, target_8)
and func_9(vstate_986, target_9)
and vstate_986.getType().hasName("tftp_state_data_t *")
and vblksize_987.getType().hasName("int")
and vstate_986.(LocalVariable).getFunction() = func
and vblksize_987.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
