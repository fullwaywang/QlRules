/**
 * @name vim-32acf1f1a72ebb9d8942b9c9d80023bf1bb668ea-ex_substitute
 * @id cpp/vim/32acf1f1a72ebb9d8942b9c9d80023bf1bb668ea/ex-substitute
 * @description vim-32acf1f1a72ebb9d8942b9c9d80023bf1bb668ea-src/ex_cmds.c-ex_substitute CVE-2022-2345
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsub_3682, Variable vsub_copy_3683, LogicalAndExpr target_5, ExprStmt target_6, ExprStmt target_7) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("char_u *")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsub_3682
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsub_copy_3683
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("char_u *")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsub_3682
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("char_u *")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_3(Variable vsub_3682, FunctionCall target_3) {
		target_3.getTarget().hasName("regtilde")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vsub_3682
		and target_3.getArgument(1).(FunctionCall).getTarget().hasName("magic_isset")
}

*/
predicate func_4(Variable vsub_3682, VariableAccess target_4) {
		target_4.getTarget()=vsub_3682
		and target_4.getParent().(AssignExpr).getLValue() = target_4
		and target_4.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("regtilde")
		and target_4.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsub_3682
		and target_4.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("magic_isset")
}

predicate func_5(Variable vsub_3682, LogicalAndExpr target_5) {
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsub_3682
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="92"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsub_3682
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="61"
}

predicate func_6(Variable vsub_3682, Variable vsub_copy_3683, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsub_copy_3683
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsub_3682
}

predicate func_7(Variable vsub_copy_3683, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("vim_free")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsub_copy_3683
}

from Function func, Variable vsub_3682, Variable vsub_copy_3683, VariableAccess target_4, LogicalAndExpr target_5, ExprStmt target_6, ExprStmt target_7
where
not func_0(vsub_3682, vsub_copy_3683, target_5, target_6, target_7)
and func_4(vsub_3682, target_4)
and func_5(vsub_3682, target_5)
and func_6(vsub_3682, vsub_copy_3683, target_6)
and func_7(vsub_copy_3683, target_7)
and vsub_3682.getType().hasName("char_u *")
and vsub_copy_3683.getType().hasName("char_u *")
and vsub_3682.getParentScope+() = func
and vsub_copy_3683.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
