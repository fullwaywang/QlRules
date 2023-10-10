/**
 * @name linux-a1616a5ac99ede5d605047a9012481ce7ff18b16-do_hidp_sock_ioctl
 * @id cpp/linux/a1616a5ac99ede5d605047a9012481ce7ff18b16/do-hidp-sock-ioctl
 * @description linux-a1616a5ac99ede5d605047a9012481ce7ff18b16-do_hidp_sock_ioctl CVE-2011-1079
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vca_51) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="name"
		and target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vca_51
		and target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getValue()="127"
		and target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getTarget().getName()="name"
		and target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vca_51
		and target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

from Function func, Variable vca_51
where
not func_0(vca_51)
and vca_51.getType().hasName("hidp_connadd_req")
and vca_51.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
