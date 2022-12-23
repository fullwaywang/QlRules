/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_ssc_setup_dul
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-ssc-setup-dul
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_ssc_setup_dul 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vipaddr_1305) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("strscpy")
		and target_0.getArgument(0) instanceof PointerFieldAccess
		and target_0.getArgument(1).(VariableAccess).getTarget()=vipaddr_1305
		and target_0.getArgument(2) instanceof SubExpr)
}

predicate func_1(Variable vwork_1309) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="nsui_ipaddr"
		and target_1.getQualifier().(VariableAccess).getTarget()=vwork_1309
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_2(Variable vwork_1309) {
	exists(SubExpr target_2 |
		target_2.getValue()="63"
		and target_2.getLeftOperand().(SizeofExprOperator).getValue()="64"
		and target_2.getLeftOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getTarget().getName()="nsui_ipaddr"
		and target_2.getLeftOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwork_1309
		and target_2.getRightOperand().(Literal).getValue()="1"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_4(Parameter vipaddr_1305) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("strlcpy")
		and target_4.getArgument(0) instanceof PointerFieldAccess
		and target_4.getArgument(1).(VariableAccess).getTarget()=vipaddr_1305
		and target_4.getArgument(2) instanceof SubExpr)
}

from Function func, Variable vwork_1309, Parameter vipaddr_1305
where
not func_0(vipaddr_1305)
and func_1(vwork_1309)
and func_2(vwork_1309)
and func_4(vipaddr_1305)
and vwork_1309.getType().hasName("nfsd4_ssc_umount_item *")
and vipaddr_1305.getType().hasName("char *")
and vwork_1309.getParentScope+() = func
and vipaddr_1305.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
