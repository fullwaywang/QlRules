/**
 * @name openssh-955854cafca88e0cdcd3d09ca1ad4ada465364a1-sink
 * @id cpp/openssh/955854cafca88e0cdcd3d09ca1ad4ada465364a1/sink
 * @description openssh-955854cafca88e0cdcd3d09ca1ad4ada465364a1-scp.c-sink CVE-2020-12062
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vvect_1243, Variable vtv_1246, ExprStmt target_5, UnaryMinusExpr target_0) {
		target_0.getValue()="-1"
		and target_0.getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("utimes")
		and target_0.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvect_1243
		and target_0.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtv_1246
		and target_0.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_1(Function func, FunctionCall target_1) {
		target_1.getTarget().hasName("strerror")
		and target_1.getArgument(0).(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_1.getEnclosingFunction() = func
}

/*predicate func_2(Variable vvect_1243, Variable vtv_1246, FunctionCall target_2) {
		target_2.getTarget().hasName("utimes")
		and target_2.getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvect_1243
		and target_2.getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_2.getArgument(1).(VariableAccess).getTarget()=vtv_1246
}

*/
predicate func_3(Variable vvect_1243, VariableAccess target_6, IfStmt target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_3.getCondition().(EqualityOperation).getAnOperand() instanceof UnaryMinusExpr
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("run_err")
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s: set times: %s"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvect_1243
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof FunctionCall
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

/*predicate func_4(Variable vvect_1243, FunctionCall target_4) {
		target_4.getTarget().hasName("run_err")
		and target_4.getArgument(0).(StringLiteral).getValue()="%s: set times: %s"
		and target_4.getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvect_1243
		and target_4.getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getArgument(2) instanceof FunctionCall
}

*/
predicate func_5(ExprStmt target_5) {
		target_5.getExpr() instanceof FunctionCall
}

predicate func_6(Variable vsetimes_1242, VariableAccess target_6) {
		target_6.getTarget()=vsetimes_1242
}

from Function func, Variable vsetimes_1242, Variable vvect_1243, Variable vtv_1246, UnaryMinusExpr target_0, FunctionCall target_1, IfStmt target_3, ExprStmt target_5, VariableAccess target_6
where
func_0(vvect_1243, vtv_1246, target_5, target_0)
and func_1(func, target_1)
and func_3(vvect_1243, target_6, target_3)
and func_5(target_5)
and func_6(vsetimes_1242, target_6)
and vsetimes_1242.getType().hasName("int")
and vvect_1243.getType().hasName("char *[1]")
and vtv_1246.getType().hasName("timeval[2]")
and vsetimes_1242.getParentScope+() = func
and vvect_1243.getParentScope+() = func
and vtv_1246.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
