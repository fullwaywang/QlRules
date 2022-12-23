/**
 * @name linux-9453264ef58638ce8976121ac44c07a3ef375983-go7007_snd_init
 * @id cpp/linux/9453264ef58638ce8976121ac44c07a3ef375983/go7007-snd-init
 * @description linux-9453264ef58638ce8976121ac44c07a3ef375983-go7007_snd_init 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vret_223) {
	exists(GotoStmt target_0 |
		target_0.toString() = "goto ..."
		and target_0.getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_223
		and target_0.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_4(Function func) {
	exists(LabelStmt target_4 |
		target_4.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(28)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(28).getFollowingStmt()=target_4))
}

predicate func_6(Variable vgosnd_222, Variable vret_223) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgosnd_222
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_223
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_7(Variable vret_223) {
	exists(ReturnStmt target_7 |
		target_7.getExpr().(VariableAccess).getTarget()=vret_223
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_223
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_8(Variable vgosnd_222, Variable vret_223) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("snd_card_free")
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="card"
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgosnd_222
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_223
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

from Function func, Variable vgosnd_222, Variable vret_223
where
not func_0(vret_223)
and not func_4(func)
and func_6(vgosnd_222, vret_223)
and func_7(vret_223)
and func_8(vgosnd_222, vret_223)
and vgosnd_222.getType().hasName("go7007_snd *")
and vret_223.getType().hasName("int")
and vgosnd_222.getParentScope+() = func
and vret_223.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
