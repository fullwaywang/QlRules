/**
 * @name linux-7b38460dc8e4eafba06c78f8e37099d3b34d473c-xfs_attr_shortform_addname
 * @id cpp/linux/7b38460dc8e4eafba06c78f8e37099d3b34d473c/xfs_attr_shortform_addname
 * @description linux-7b38460dc8e4eafba06c78f8e37099d3b34d473c-xfs_attr_shortform_addname 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vretval_503) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vretval_503
		and target_0.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vretval_503
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vretval_503
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="17")
}

predicate func_1(Parameter vargs_501) {
	exists(AssignAndExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vargs_501
		and target_1.getRValue().(ComplementExpr).getValue()="-33"
		and target_1.getRValue().(ComplementExpr).getOperand().(Literal).getValue()="32")
}

predicate func_3(Variable vretval_503) {
	exists(ConditionalExpr target_3 |
		target_3.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_3.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vretval_503
		and target_3.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_3.getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_3.getThen() instanceof Literal
		and target_3.getElse().(FunctionCall).getTarget().hasName("assfail")
		and target_3.getElse().(FunctionCall).getArgument(0).(StringLiteral).getValue()="retval == 0"
		and target_3.getElse().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_3.getElse().(FunctionCall).getArgument(2) instanceof Literal)
}

predicate func_4(Variable vretval_503, Parameter vargs_501) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=vretval_503
		and target_4.getRValue().(FunctionCall).getTarget().hasName("xfs_attr_shortform_remove")
		and target_4.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vargs_501)
}

predicate func_5(Parameter vargs_501) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("xfs_attr_shortform_remove")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vargs_501)
}

from Function func, Variable vretval_503, Parameter vargs_501
where
not func_0(vretval_503)
and not func_1(vargs_501)
and func_3(vretval_503)
and vretval_503.getType().hasName("int")
and func_4(vretval_503, vargs_501)
and vargs_501.getType().hasName("xfs_da_args_t *")
and func_5(vargs_501)
and vretval_503.getParentScope+() = func
and vargs_501.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
