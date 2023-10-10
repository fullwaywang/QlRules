/**
 * @name libtiff-aaab5c3c9d2a2c6984f23ccbc79702610439bc65-LogL16Encode
 * @id cpp/libtiff/aaab5c3c9d2a2c6984f23ccbc79702610439bc65/LogL16Encode
 * @description libtiff-aaab5c3c9d2a2c6984f23ccbc79702610439bc65-libtiff/tif_luv.c-LogL16Encode NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable v__PRETTY_FUNCTION__, FunctionCall target_0) {
		target_0.getTarget().hasName("__assert_fail")
		and not target_0.getTarget().hasName("TIFFErrorExt")
		and target_0.getArgument(0).(StringLiteral).getValue()="sp->tbuflen >= npixels"
		and target_0.getArgument(1) instanceof StringLiteral
		and target_0.getArgument(2) instanceof Literal
		and target_0.getArgument(3).(VariableAccess).getTarget()=v__PRETTY_FUNCTION__
}

predicate func_1(Variable vsp_416, Variable vnpixels_420, ExprStmt target_11, ExprStmt target_12) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(PointerFieldAccess).getTarget().getName()="tbuflen"
		and target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_416
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vnpixels_420
		and target_1.getParent().(IfStmt).getThen() instanceof EmptyStmt
		and target_11.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vtif_414, ExprStmt target_13) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="tif_clientdata"
		and target_2.getQualifier().(VariableAccess).getTarget()=vtif_414
		and target_2.getQualifier().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Function func) {
	exists(ReturnStmt target_4 |
		target_4.getExpr().(Literal).getValue()="0"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vsp_416, Variable vnpixels_420, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="tbuflen"
		and target_5.getQualifier().(VariableAccess).getTarget()=vsp_416
		and target_5.getParent().(GEExpr).getLesserOperand().(VariableAccess).getTarget()=vnpixels_420
}

/*predicate func_6(Variable vsp_416, Variable vnpixels_420, VariableAccess target_6) {
		target_6.getTarget()=vnpixels_420
		and target_6.getParent().(GEExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tbuflen"
		and target_6.getParent().(GEExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_416
}

*/
predicate func_7(Variable vsp_416, Variable vnpixels_420, CommaExpr target_7) {
		target_7.getLeftOperand().(SizeofExprOperator).getValue()="4"
		and target_7.getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tbuflen"
		and target_7.getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_416
		and target_7.getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnpixels_420
		and target_7.getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr() instanceof FunctionCall
}

/*predicate func_8(Variable vsp_416, Variable vnpixels_420, PointerDereferenceExpr target_14, ExprStmt target_15, RelationalOperation target_8) {
		 (target_8 instanceof GEExpr or target_8 instanceof LEExpr)
		and target_8.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tbuflen"
		and target_8.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_416
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vnpixels_420
		and target_8.getParent().(IfStmt).getThen() instanceof EmptyStmt
		and target_8.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getLesserOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(ExprCall).getArgument(2).(VariableAccess).getLocation())
}

*/
/*predicate func_9(RelationalOperation target_8, Function func, EmptyStmt target_9) {
		target_9.getParent().(IfStmt).getCondition()=target_8
		and target_9.getEnclosingFunction() = func
}

*/
/*predicate func_10(RelationalOperation target_8, Function func, ExprStmt target_10) {
		target_10.getExpr() instanceof FunctionCall
		and target_10.getParent().(IfStmt).getCondition()=target_8
		and target_10.getEnclosingFunction() = func
}

*/
predicate func_11(Variable vsp_416, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int16 *")
		and target_11.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="tbuf"
		and target_11.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_416
}

predicate func_12(Variable vsp_416, Variable vnpixels_420, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnpixels_420
		and target_12.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_12.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="pixel_size"
		and target_12.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_416
}

predicate func_13(Parameter vtif_414, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint8 *")
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="tif_rawcp"
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_414
}

predicate func_14(Variable vsp_416, PointerDereferenceExpr target_14) {
		target_14.getOperand().(PointerFieldAccess).getTarget().getName()="tfunc"
		and target_14.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_416
}

predicate func_15(Variable vsp_416, Variable vnpixels_420, ExprStmt target_15) {
		target_15.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tfunc"
		and target_15.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_416
		and target_15.getExpr().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vsp_416
		and target_15.getExpr().(ExprCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("uint8 *")
		and target_15.getExpr().(ExprCall).getArgument(2).(VariableAccess).getTarget()=vnpixels_420
}

from Function func, Parameter vtif_414, Variable vsp_416, Variable vnpixels_420, Variable v__PRETTY_FUNCTION__, FunctionCall target_0, PointerFieldAccess target_5, CommaExpr target_7, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, PointerDereferenceExpr target_14, ExprStmt target_15
where
func_0(v__PRETTY_FUNCTION__, target_0)
and not func_1(vsp_416, vnpixels_420, target_11, target_12)
and not func_2(vtif_414, target_13)
and not func_4(func)
and func_5(vsp_416, vnpixels_420, target_5)
and func_7(vsp_416, vnpixels_420, target_7)
and func_11(vsp_416, target_11)
and func_12(vsp_416, vnpixels_420, target_12)
and func_13(vtif_414, target_13)
and func_14(vsp_416, target_14)
and func_15(vsp_416, vnpixels_420, target_15)
and vtif_414.getType().hasName("TIFF *")
and vsp_416.getType().hasName("LogLuvState *")
and vnpixels_420.getType().hasName("tmsize_t")
and v__PRETTY_FUNCTION__.getType() instanceof ArrayType
and vtif_414.getFunction() = func
and vsp_416.(LocalVariable).getFunction() = func
and vnpixels_420.(LocalVariable).getFunction() = func
and not v__PRETTY_FUNCTION__.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
