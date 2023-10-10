/**
 * @name linux-f4020438fab05364018c91f7e02ebdd192085933-xfs_attr_shortform_verify
 * @id cpp/linux/f4020438fab05364018c91f7e02ebdd192085933/xfs_attr_shortform_verify
 * @description linux-f4020438fab05364018c91f7e02ebdd192085933-xfs_attr_shortform_verify 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vendp_1014) {
	exists(PointerArithmeticOperation target_0 |
		target_0.getLeftOperand() instanceof PointerArithmeticOperation
		and target_0.getRightOperand().(Literal).getValue()="1"
		and target_0.getParent().(GEExpr).getLesserOperand().(VariableAccess).getTarget()=vendp_1014
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(LabelStmt).toString() = "label ...:"
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(AsmStmt).toString() = "asm statement"
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(LabelLiteral).getValue()="&&__here")
}

predicate func_1(Variable vsfep_1012, Variable vendp_1014) {
	exists(PointerArithmeticOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vsfep_1012
		and target_1.getAnOperand().(SizeofExprOperator).getValue()="4"
		and target_1.getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsfep_1012
		and target_1.getParent().(GEExpr).getLesserOperand().(VariableAccess).getTarget()=vendp_1014
		and target_1.getParent().(GEExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(LabelStmt).toString() = "label ...:"
		and target_1.getParent().(GEExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(AsmStmt).toString() = "asm statement"
		and target_1.getParent().(GEExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(LabelLiteral).getValue()="&&__here")
}

from Function func, Variable vsfep_1012, Variable vendp_1014
where
not func_0(vendp_1014)
and func_1(vsfep_1012, vendp_1014)
and vsfep_1012.getType().hasName("xfs_attr_sf_entry *")
and vendp_1014.getType().hasName("char *")
and vsfep_1012.getParentScope+() = func
and vendp_1014.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
