/**
 * @name cups-efbea1742bd30f842fbbfb87a473e5c84f4162f9-ippReadIO
 * @id cpp/cups/efbea1742bd30f842fbbfb87a473e5c84f4162f9/ippReadIO
 * @description cups-efbea1742bd30f842fbbfb87a473e5c84f4162f9-cups/ipp.c-ippReadIO CVE-2020-10001
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbuffer_2866, VariableAccess target_0) {
		target_0.getTarget()=vbuffer_2866
}

predicate func_2(Variable vn_2865, Variable vbuffer_2866, VariableAccess target_13, LogicalOrExpr target_14, ExprStmt target_15, ExprStmt target_16) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("unsigned char *")
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuffer_2866
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vn_2865
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_13
		and target_14.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Variable vn_2865, BlockStmt target_17) {
	exists(RelationalOperation target_4 |
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(PointerArithmeticOperation).getAnOperand() instanceof PointerArithmeticOperation
		and target_4.getGreaterOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_4.getLesserOperand().(VariableAccess).getType().hasName("unsigned char *")
		and target_4.getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vn_2865
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SizeofExprOperator).getValue()="1024"
		and target_4.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_17)
}

predicate func_5(BlockStmt target_18, Function func) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand() instanceof PointerArithmeticOperation
		and target_5.getLesserOperand().(VariableAccess).getType().hasName("unsigned char *")
		and target_5.getParent().(IfStmt).getThen()=target_18
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable vn_2865, Variable vbufptr_2869, PointerArithmeticOperation target_6) {
		target_6.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbufptr_2869
		and target_6.getAnOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_6.getAnOperand().(VariableAccess).getTarget()=vn_2865
}

predicate func_7(Variable vn_2865, Variable vbuffer_2866, Variable vbufptr_2869, BlockStmt target_18, PointerArithmeticOperation target_7) {
		target_7.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbufptr_2869
		and target_7.getAnOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_7.getAnOperand().(VariableAccess).getTarget()=vn_2865
		and target_7.getParent().(GEExpr).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuffer_2866
		and target_7.getParent().(GEExpr).getLesserOperand().(PointerArithmeticOperation).getAnOperand() instanceof AddExpr
		and target_7.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_18
}

predicate func_9(Variable vn_2865, Variable vbuffer_2866, BlockStmt target_17, RelationalOperation target_9) {
		 (target_9 instanceof GEExpr or target_9 instanceof LEExpr)
		and target_9.getGreaterOperand() instanceof PointerArithmeticOperation
		and target_9.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuffer_2866
		and target_9.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(AddExpr).getValue()="32769"
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vn_2865
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SizeofExprOperator).getValue()="1024"
		and target_9.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_17
}

/*predicate func_10(Function func, AddExpr target_10) {
		target_10.getValue()="32769"
		and target_10.getEnclosingFunction() = func
}

*/
predicate func_11(Variable vbuffer_2866, BlockStmt target_18, RelationalOperation target_11) {
		 (target_11 instanceof GEExpr or target_11 instanceof LEExpr)
		and target_11.getGreaterOperand() instanceof PointerArithmeticOperation
		and target_11.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuffer_2866
		and target_11.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(AddExpr).getValue()="32769"
		and target_11.getParent().(IfStmt).getThen()=target_18
}

/*predicate func_12(Function func, AddExpr target_12) {
		target_12.getValue()="32769"
		and target_12.getEnclosingFunction() = func
}

*/
predicate func_13(Variable vtag_2871, VariableAccess target_13) {
		target_13.getTarget()=vtag_2871
}

predicate func_14(Variable vn_2865, LogicalOrExpr target_14) {
		target_14.getAnOperand() instanceof RelationalOperation
		and target_14.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vn_2865
		and target_14.getAnOperand().(RelationalOperation).getLesserOperand().(SizeofExprOperator).getValue()="1024"
}

predicate func_15(Variable vbuffer_2866, Variable vbufptr_2869, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbufptr_2869
		and target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbuffer_2866
}

predicate func_16(Variable vbuffer_2866, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("_cupsBufferRelease")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_2866
}

predicate func_17(Variable vbuffer_2866, BlockStmt target_17) {
		target_17.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_cupsSetError")
		and target_17.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="IPP language length overflows value."
		and target_17.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_17.getStmt(1).(EmptyStmt).toString() = ";"
		and target_17.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_cupsBufferRelease")
		and target_17.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_2866
}

predicate func_18(Variable vbuffer_2866, BlockStmt target_18) {
		target_18.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_cupsSetError")
		and target_18.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="IPP string length overflows value."
		and target_18.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_18.getStmt(1).(EmptyStmt).toString() = ";"
		and target_18.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_cupsBufferRelease")
		and target_18.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_2866
}

from Function func, Variable vn_2865, Variable vbuffer_2866, Variable vbufptr_2869, Variable vtag_2871, VariableAccess target_0, PointerArithmeticOperation target_6, PointerArithmeticOperation target_7, RelationalOperation target_9, RelationalOperation target_11, VariableAccess target_13, LogicalOrExpr target_14, ExprStmt target_15, ExprStmt target_16, BlockStmt target_17, BlockStmt target_18
where
func_0(vbuffer_2866, target_0)
and not func_2(vn_2865, vbuffer_2866, target_13, target_14, target_15, target_16)
and not func_4(vn_2865, target_17)
and not func_5(target_18, func)
and func_6(vn_2865, vbufptr_2869, target_6)
and func_7(vn_2865, vbuffer_2866, vbufptr_2869, target_18, target_7)
and func_9(vn_2865, vbuffer_2866, target_17, target_9)
and func_11(vbuffer_2866, target_18, target_11)
and func_13(vtag_2871, target_13)
and func_14(vn_2865, target_14)
and func_15(vbuffer_2866, vbufptr_2869, target_15)
and func_16(vbuffer_2866, target_16)
and func_17(vbuffer_2866, target_17)
and func_18(vbuffer_2866, target_18)
and vn_2865.getType().hasName("int")
and vbuffer_2866.getType().hasName("unsigned char *")
and vbufptr_2869.getType().hasName("unsigned char *")
and vtag_2871.getType().hasName("ipp_tag_t")
and vn_2865.getParentScope+() = func
and vbuffer_2866.getParentScope+() = func
and vbufptr_2869.getParentScope+() = func
and vtag_2871.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
