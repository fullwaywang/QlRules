import cpp

predicate func_0(Variable vcur_4353, Variable vinsert_4353, Variable vcopy_4358) {
	exists(BinaryLogicalOperation target_0 |
		target_0.getType() instanceof IntType
		and target_0.getAnOperand().(EqualityOperation).getType() instanceof IntType
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getType() instanceof CTypedefType
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4353
		and target_0.getAnOperand().(EqualityOperation).getType() instanceof IntType
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="children"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getType() instanceof PointerType
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4353
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcur_4353
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="children"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4353
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vinsert_4353
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcopy_4358)
}

predicate func_1(Variable vcur_4353, Variable vinsert_4353, Variable vcopy_4358) {
	exists(EqualityOperation target_1 |
		target_1.getType() instanceof IntType
		and target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="children"
		and target_1.getAnOperand().(PointerFieldAccess).getType() instanceof PointerType
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4353
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcur_4353
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="children"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4353
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vinsert_4353
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcopy_4358)
}

from Function func, Variable vcur_4353, Variable vinsert_4353, Variable vcopy_4358
where
not func_0(vcur_4353, vinsert_4353, vcopy_4358)
and func_1(vcur_4353, vinsert_4353, vcopy_4358)
and vcur_4353.getType().hasName("xmlNodePtr")
and vinsert_4353.getType().hasName("xmlNodePtr")
and vcopy_4358.getType().hasName("xmlNodePtr")
and vcur_4353.getParentScope+() = func
and vinsert_4353.getParentScope+() = func
and vcopy_4358.getParentScope+() = func
select func, vcur_4353, vinsert_4353, vcopy_4358
