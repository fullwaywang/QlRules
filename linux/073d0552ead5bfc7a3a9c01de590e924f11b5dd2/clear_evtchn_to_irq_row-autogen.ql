/**
 * @name linux-073d0552ead5bfc7a3a9c01de590e924f11b5dd2-clear_evtchn_to_irq_row
 * @id cpp/linux/073d0552ead5bfc7a3a9c01de590e924f11b5dd2/clear_evtchn_to_irq_row
 * @description linux-073d0552ead5bfc7a3a9c01de590e924f11b5dd2-clear_evtchn_to_irq_row 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vrow_103, Variable vcol_105, Variable vevtchn_to_irq) {
	exists(DoStmt target_0 |
		target_0.getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(FunctionDeclarationEntry).getType() instanceof VoidType
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand() instanceof ArrayExpr
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="1"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vevtchn_to_irq
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vrow_103
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcol_105
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="2"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vevtchn_to_irq
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vrow_103
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcol_105
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="4"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vevtchn_to_irq
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vrow_103
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcol_105
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="8"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vevtchn_to_irq
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vrow_103
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcol_105
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="8"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__compiletime_assert_1478")
		and target_0.getStmt().(BlockStmt).getStmt(1).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vevtchn_to_irq
		and target_0.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vrow_103
		and target_0.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcol_105
		and target_0.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

predicate func_8(Parameter vrow_103, Variable vcol_105, Variable vevtchn_to_irq) {
	exists(ArrayExpr target_8 |
		target_8.getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vevtchn_to_irq
		and target_8.getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vrow_103
		and target_8.getArrayOffset().(VariableAccess).getTarget()=vcol_105
		and target_8.getParent().(AssignExpr).getLValue() = target_8
		and target_8.getParent().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and target_8.getParent().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

predicate func_9(Variable vcol_105) {
	exists(PostfixIncrExpr target_9 |
		target_9.getOperand().(VariableAccess).getTarget()=vcol_105)
}

predicate func_10(Variable vevtchn_to_irq) {
	exists(PointerDereferenceExpr target_10 |
		target_10.getOperand().(VariableAccess).getTarget()=vevtchn_to_irq)
}

from Function func, Parameter vrow_103, Variable vcol_105, Variable vevtchn_to_irq
where
not func_0(vrow_103, vcol_105, vevtchn_to_irq)
and func_8(vrow_103, vcol_105, vevtchn_to_irq)
and vrow_103.getType().hasName("unsigned int")
and vcol_105.getType().hasName("unsigned int")
and func_9(vcol_105)
and vevtchn_to_irq.getType().hasName("int **")
and func_10(vevtchn_to_irq)
and vrow_103.getParentScope+() = func
and vcol_105.getParentScope+() = func
and not vevtchn_to_irq.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
