/**
 * @name libpng-7e1ca9ceba4e64259863efdd98bab9b55bdc0b9c-png_handle_pCAL
 * @id cpp/libpng/7e1ca9ceba4e64259863efdd98bab9b55bdc0b9c/png-handle-pCAL
 * @description libpng-7e1ca9ceba4e64259863efdd98bab9b55bdc0b9c-pngrutil.c-png_handle_pCAL CVE-2015-8472
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vslength_1670, BlockStmt target_2, ExprStmt target_3) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vslength_1670
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="12"
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbuf_1668, Variable vendptr_1668, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vendptr_1668
		and target_1.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_1668
		and target_1.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="12"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_warning")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Invalid pCAL data"
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_free")
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="chunkdata"
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="chunkdata"
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_3(Variable vendptr_1668, Variable vslength_1670, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vendptr_1668
		and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="chunkdata"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vslength_1670
}

from Function func, Variable vbuf_1668, Variable vendptr_1668, Variable vslength_1670, RelationalOperation target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vslength_1670, target_2, target_3)
and func_1(vbuf_1668, vendptr_1668, target_2, target_1)
and func_2(target_2)
and func_3(vendptr_1668, vslength_1670, target_3)
and vbuf_1668.getType().hasName("png_charp")
and vendptr_1668.getType().hasName("png_charp")
and vslength_1670.getType().hasName("png_size_t")
and vbuf_1668.getParentScope+() = func
and vendptr_1668.getParentScope+() = func
and vslength_1670.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
