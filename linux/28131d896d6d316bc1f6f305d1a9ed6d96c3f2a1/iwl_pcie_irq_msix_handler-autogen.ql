/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_pcie_irq_msix_handler
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-pcie-irq-msix-handler
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_pcie_irq_msix_handler CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_5(Function func) {
	exists(DeclStmt target_5 |
		target_5.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and func.getEntryPoint().(BlockStmt).getStmt(7)=target_5)
}

predicate func_8(Variable vtrans_2147) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("bool")
		and target_8.getExpr().(AssignExpr).getRValue() instanceof BitwiseAndExpr
		and target_8.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="device_family"
		and target_8.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trans_cfg"
		and target_8.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_2147)
}

predicate func_10(Variable vtrans_2147, Variable visr_stats_2148, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition() instanceof BitwiseAndExpr
		and target_10.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(FunctionDeclarationEntry).getType() instanceof VoidType
		and target_10.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(StringLiteral).getValue()="Hardware error detected. Restarting.\n"
		and target_10.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="Hardware error detected. Restarting.\n"
		and target_10.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_10.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_10.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__compiletime_assert_1813")
		and target_10.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__iwl_err")
		and target_10.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dev"
		and target_10.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_2147
		and target_10.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Hardware error detected. Restarting.\n"
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hw"
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=visr_stats_2148
		and target_10.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="hw_error"
		and target_10.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dbg"
		and target_10.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_2147
		and target_10.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("iwl_pcie_irq_handle_error")
		and target_10.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrans_2147
		and (func.getEntryPoint().(BlockStmt).getStmt(32)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(32).getFollowingStmt()=target_10))
}

predicate func_11(Variable vtrans_2147, Variable vinta_fh_2150, Variable vinta_hw_2150) {
	exists(BitwiseAndExpr target_11 |
		target_11.getLeftOperand().(VariableAccess).getTarget()=vinta_hw_2150
		and target_11.getParent().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vinta_fh_2150
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(FunctionDeclarationEntry).getType() instanceof VoidType
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(StringLiteral).getValue()="Microcode SW error detected. Restarting 0x%X.\n"
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="Microcode SW error detected. Restarting 0x%X.\n"
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__compiletime_assert_1806")
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__iwl_err")
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dev"
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_2147
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof EnumConstantAccess
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Microcode SW error detected. Restarting 0x%X.\n"
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vinta_fh_2150)
}

predicate func_12(Variable vtrans_2147, Variable vinta_hw_2150) {
	exists(BitwiseAndExpr target_12 |
		target_12.getLeftOperand().(VariableAccess).getTarget()=vinta_hw_2150
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(FunctionDeclarationEntry).getType() instanceof VoidType
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(StringLiteral).getValue()="Microcode CT kill error detected.\n"
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="Microcode CT kill error detected.\n"
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__compiletime_assert_1812")
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__iwl_err")
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dev"
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_2147
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof EnumConstantAccess
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Microcode CT kill error detected.\n")
}

predicate func_13(Variable vtrans_2147, Variable vinta_hw_2150) {
	exists(BitwiseAndExpr target_13 |
		target_13.getLeftOperand().(VariableAccess).getTarget()=vinta_hw_2150
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(FunctionDeclarationEntry).getType() instanceof VoidType
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(StringLiteral).getValue()="Hardware error detected. Restarting.\n"
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="Hardware error detected. Restarting.\n"
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__compiletime_assert_1813")
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__iwl_err")
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dev"
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_2147
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof EnumConstantAccess
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Hardware error detected. Restarting.\n")
}

predicate func_15(Variable vtrans_2147) {
	exists(PointerFieldAccess target_15 |
		target_15.getTarget().getName()="dev"
		and target_15.getQualifier().(VariableAccess).getTarget()=vtrans_2147)
}

predicate func_16(Variable vinta_fh_2150, Variable vinta_hw_2150) {
	exists(BitwiseOrExpr target_16 |
		target_16.getLeftOperand().(VariableAccess).getTarget()=vinta_fh_2150
		and target_16.getRightOperand().(VariableAccess).getTarget()=vinta_hw_2150)
}

from Function func, Variable vtrans_2147, Variable visr_stats_2148, Variable vinta_fh_2150, Variable vinta_hw_2150
where
not func_5(func)
and not func_8(vtrans_2147)
and not func_10(vtrans_2147, visr_stats_2148, func)
and func_11(vtrans_2147, vinta_fh_2150, vinta_hw_2150)
and func_12(vtrans_2147, vinta_hw_2150)
and func_13(vtrans_2147, vinta_hw_2150)
and vtrans_2147.getType().hasName("iwl_trans *")
and func_15(vtrans_2147)
and visr_stats_2148.getType().hasName("isr_statistics *")
and vinta_fh_2150.getType().hasName("u32")
and vinta_hw_2150.getType().hasName("u32")
and func_16(vinta_fh_2150, vinta_hw_2150)
and vtrans_2147.getParentScope+() = func
and visr_stats_2148.getParentScope+() = func
and vinta_fh_2150.getParentScope+() = func
and vinta_hw_2150.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
