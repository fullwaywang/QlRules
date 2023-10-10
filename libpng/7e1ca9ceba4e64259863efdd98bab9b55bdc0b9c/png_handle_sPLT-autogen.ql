/**
 * @name libpng-7e1ca9ceba4e64259863efdd98bab9b55bdc0b9c-png_handle_sPLT
 * @id cpp/libpng/7e1ca9ceba4e64259863efdd98bab9b55bdc0b9c/png-handle-sPLT
 * @description libpng-7e1ca9ceba4e64259863efdd98bab9b55bdc0b9c-pngrutil.c-png_handle_sPLT CVE-2015-8472
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vslength_1185, BlockStmt target_2, ExprStmt target_3, RelationalOperation target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vslength_1185
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2"
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpng_ptr_1175, Variable ventry_start_1178, Variable vslength_1185, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=ventry_start_1178
		and target_1.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="chunkdata"
		and target_1.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1175
		and target_1.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vslength_1185
		and target_1.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="2"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vpng_ptr_1175, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_free")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_1175
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="chunkdata"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1175
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="chunkdata"
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1175
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_3(Parameter vpng_ptr_1175, Variable vslength_1185, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="chunkdata"
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1175
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vslength_1185
		and target_3.getExpr().(AssignExpr).getRValue().(HexLiteral).getValue()="0"
}

from Function func, Parameter vpng_ptr_1175, Variable ventry_start_1178, Variable vslength_1185, RelationalOperation target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vslength_1185, target_2, target_3, target_1)
and func_1(vpng_ptr_1175, ventry_start_1178, vslength_1185, target_2, target_1)
and func_2(vpng_ptr_1175, target_2)
and func_3(vpng_ptr_1175, vslength_1185, target_3)
and vpng_ptr_1175.getType().hasName("png_structp")
and ventry_start_1178.getType().hasName("png_bytep")
and vslength_1185.getType().hasName("png_size_t")
and vpng_ptr_1175.getParentScope+() = func
and ventry_start_1178.getParentScope+() = func
and vslength_1185.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
