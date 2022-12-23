/**
 * @name linux-c444eb564fb16645c172d550359cb3d75fe8a040-__split_huge_pmd
 * @id cpp/linux/c444eb564fb16645c172d550359cb3d75fe8a040/__split_huge_pmd
 * @description linux-c444eb564fb16645c172d550359cb3d75fe8a040-__split_huge_pmd 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		func.getEntryPoint().(BlockStmt).getStmt(2)=target_0)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and func.getEntryPoint().(BlockStmt).getStmt(3)=target_1)
}

predicate func_3(Parameter vpage_2384) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("PageLocked")
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_2384
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getCondition() instanceof Literal
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0) instanceof StringLiteral
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(1) instanceof Literal
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand() instanceof Literal
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="9"
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getValue()="12"
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0).(Literal).getValue()="615"
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vpage_2384)
}

predicate func_12(Parameter vpage_2384) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("bool")
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vpage_2384)
}

predicate func_13(Parameter vpage_2384) {
	exists(IfStmt target_13 |
		target_13.getCondition() instanceof EqualityOperation
		and target_13.getThen().(GotoStmt).toString() = "goto ..."
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vpage_2384)
}

predicate func_14(Parameter vpmd_2383, Parameter vpage_2384, Variable vptl_2386, Function func) {
	exists(IfStmt target_14 |
		target_14.getCondition() instanceof FunctionCall
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vpage_2384
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("trylock_page")
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_2384
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("get_page")
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_2384
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("pmd_t")
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpmd_2383
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("lock_page")
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_2384
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("spin_lock")
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptl_2386
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("pmd_same")
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpmd_2383
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("pmd_t")
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("unlock_page")
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_2384
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("put_page")
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_2384
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpage_2384
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(3).(GotoStmt).toString() = "goto ..."
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("put_page")
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_2384
		and target_14.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_14.getElse() instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_14 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_14))
}

predicate func_27(Function func) {
	exists(LabelStmt target_27 |
		target_27.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_27 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_27))
}

predicate func_28(Variable vptl_2386, Function func) {
	exists(ExprStmt target_28 |
		target_28.getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_28.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptl_2386
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_28 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_28))
}

predicate func_29(Parameter vpage_2384, Function func) {
	exists(IfStmt target_29 |
		target_29.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("bool")
		and target_29.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vpage_2384
		and target_29.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("unlock_page")
		and target_29.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_2384
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_29 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_29))
}

predicate func_31(Parameter vpmd_2383, Parameter vpage_2384, Variable vvmemmap_base) {
	exists(EqualityOperation target_31 |
		target_31.getAnOperand().(VariableAccess).getTarget()=vpage_2384
		and target_31.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vvmemmap_base
		and target_31.getAnOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getTarget().hasName("pmd_pfn")
		and target_31.getAnOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpmd_2383
		and target_31.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_33(Parameter vpmd_2383, Parameter vpage_2384, Variable vvmemmap_base) {
	exists(ExprStmt target_33 |
		target_33.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpage_2384
		and target_33.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vvmemmap_base
		and target_33.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getTarget().hasName("pmd_pfn")
		and target_33.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpmd_2383
		and target_33.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("pmd_trans_huge")
		and target_33.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpmd_2383)
}

predicate func_34(Parameter vpmd_2383, Parameter vpage_2384) {
	exists(IfStmt target_34 |
		target_34.getCondition().(FunctionCall).getTarget().hasName("PageMlocked")
		and target_34.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_2384
		and target_34.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("clear_page_mlock")
		and target_34.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_2384
		and target_34.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("pmd_trans_huge")
		and target_34.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpmd_2383)
}

predicate func_35(Parameter vpmd_2383) {
	exists(IfStmt target_35 |
		target_35.getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("pmd_devmap")
		and target_35.getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpmd_2383
		and target_35.getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("is_pmd_migration_entry")
		and target_35.getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpmd_2383
		and target_35.getThen().(GotoStmt).toString() = "goto ..."
		and target_35.getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("pmd_trans_huge")
		and target_35.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpmd_2383)
}

predicate func_37(Parameter vpmd_2383) {
	exists(PointerDereferenceExpr target_37 |
		target_37.getOperand().(VariableAccess).getTarget()=vpmd_2383
		and target_37.getParent().(FunctionCall).getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("is_pmd_migration_entry"))
}

predicate func_38(Parameter vpage_2384) {
	exists(NotExpr target_38 |
		target_38.getOperand().(VariableAccess).getTarget()=vpage_2384)
}

predicate func_40(Parameter vpage_2384) {
	exists(FunctionCall target_40 |
		target_40.getTarget().hasName("clear_page_mlock")
		and target_40.getArgument(0).(VariableAccess).getTarget()=vpage_2384)
}

predicate func_41(Parameter vvma_2383, Parameter vpmd_2383, Variable vptl_2386) {
	exists(AssignExpr target_41 |
		target_41.getLValue().(VariableAccess).getTarget()=vptl_2386
		and target_41.getRValue().(FunctionCall).getTarget().hasName("pmd_lock")
		and target_41.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vm_mm"
		and target_41.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_2383
		and target_41.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpmd_2383)
}

from Function func, Parameter vvma_2383, Parameter vpmd_2383, Parameter vpage_2384, Variable vptl_2386, Variable vvmemmap_base
where
not func_0(func)
and not func_1(func)
and not func_3(vpage_2384)
and not func_12(vpage_2384)
and not func_13(vpage_2384)
and not func_14(vpmd_2383, vpage_2384, vptl_2386, func)
and not func_27(func)
and not func_28(vptl_2386, func)
and not func_29(vpage_2384, func)
and func_31(vpmd_2383, vpage_2384, vvmemmap_base)
and func_33(vpmd_2383, vpage_2384, vvmemmap_base)
and func_34(vpmd_2383, vpage_2384)
and func_35(vpmd_2383)
and vpmd_2383.getType().hasName("pmd_t *")
and func_37(vpmd_2383)
and vpage_2384.getType().hasName("page *")
and func_38(vpage_2384)
and func_40(vpage_2384)
and vptl_2386.getType().hasName("spinlock_t *")
and func_41(vvma_2383, vpmd_2383, vptl_2386)
and vvmemmap_base.getType().hasName("unsigned long")
and vvma_2383.getParentScope+() = func
and vpmd_2383.getParentScope+() = func
and vpage_2384.getParentScope+() = func
and vptl_2386.getParentScope+() = func
and not vvmemmap_base.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
