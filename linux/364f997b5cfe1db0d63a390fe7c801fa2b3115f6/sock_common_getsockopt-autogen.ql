/**
 * @name linux-364f997b5cfe1db0d63a390fe7c801fa2b3115f6-sock_common_getsockopt
 * @id cpp/linux/364f997b5cfe1db0d63a390fe7c801fa2b3115f6/sock-common-getsockopt
 * @description linux-364f997b5cfe1db0d63a390fe7c801fa2b3115f6-sock_common_getsockopt 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsk_3611) {
	exists(StmtExpr target_0 |
		target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(FunctionDeclarationEntry).getType() instanceof VoidType
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getTarget().getName()="skc_prot"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="1"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getTarget().getName()="skc_prot"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="__sk_common"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_3611
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="2"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getTarget().getName()="skc_prot"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="__sk_common"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_3611
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="4"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getTarget().getName()="skc_prot"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="__sk_common"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_3611
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="8"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getTarget().getName()="skc_prot"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="__sk_common"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_3611
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="8"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__compiletime_assert_1547")
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PointerDereferenceExpr).getOperand().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="skc_prot"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PointerDereferenceExpr).getOperand().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="__sk_common"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PointerDereferenceExpr).getOperand().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_3611)
}

predicate func_5(Variable vsk_3611) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="__sk_common"
		and target_5.getQualifier().(VariableAccess).getTarget()=vsk_3611)
}

predicate func_6(Function func) {
	exists(ValueFieldAccess target_6 |
		target_6.getTarget().getName()="skc_prot"
		and target_6.getQualifier() instanceof PointerFieldAccess
		and target_6.getEnclosingFunction() = func)
}

from Function func, Variable vsk_3611
where
not func_0(vsk_3611)
and func_5(vsk_3611)
and func_6(func)
and vsk_3611.getType().hasName("sock *")
and vsk_3611.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
