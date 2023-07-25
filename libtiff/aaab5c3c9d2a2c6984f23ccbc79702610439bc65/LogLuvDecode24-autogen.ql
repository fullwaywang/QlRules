/**
 * @name libtiff-aaab5c3c9d2a2c6984f23ccbc79702610439bc65-LogLuvDecode24
 * @id cpp/libtiff/aaab5c3c9d2a2c6984f23ccbc79702610439bc65/LogLuvDecode24
 * @description libtiff-aaab5c3c9d2a2c6984f23ccbc79702610439bc65-libtiff/tif_luv.c-LogLuvDecode24 NULL
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

predicate func_1(Variable vsp_256, Variable vnpixels_259, EqualityOperation target_13, ExprStmt target_14) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(PointerFieldAccess).getTarget().getName()="tbuflen"
		and target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_256
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vnpixels_259
		and target_1.getParent().(IfStmt).getThen() instanceof EmptyStmt
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vtif_253, ExprStmt target_15) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="tif_clientdata"
		and target_2.getQualifier().(VariableAccess).getTarget()=vtif_253
		and target_2.getQualifier().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Variable vsp_256, Variable vnpixels_259, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="tbuflen"
		and target_5.getQualifier().(VariableAccess).getTarget()=vsp_256
		and target_5.getParent().(GEExpr).getLesserOperand().(VariableAccess).getTarget()=vnpixels_259
}

/*predicate func_6(Variable vsp_256, Variable vnpixels_259, VariableAccess target_6) {
		target_6.getTarget()=vnpixels_259
		and target_6.getParent().(GEExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tbuflen"
		and target_6.getParent().(GEExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_256
}

*/
predicate func_7(Variable vcc_257, VariableAccess target_7) {
		target_7.getTarget()=vcc_257
}

predicate func_8(Variable vsp_256, Variable vnpixels_259, CommaExpr target_8) {
		target_8.getLeftOperand().(SizeofExprOperator).getValue()="4"
		and target_8.getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tbuflen"
		and target_8.getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_256
		and target_8.getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnpixels_259
		and target_8.getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr() instanceof FunctionCall
}

/*predicate func_9(Variable vsp_256, Variable vnpixels_259, ExprStmt target_16, LogicalAndExpr target_17, RelationalOperation target_9) {
		 (target_9 instanceof GEExpr or target_9 instanceof LEExpr)
		and target_9.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tbuflen"
		and target_9.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_256
		and target_9.getLesserOperand().(VariableAccess).getTarget()=vnpixels_259
		and target_9.getParent().(IfStmt).getThen() instanceof EmptyStmt
		and target_9.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getLesserOperand().(VariableAccess).getLocation().isBefore(target_17.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_10(RelationalOperation target_9, Function func, EmptyStmt target_10) {
		target_10.getParent().(IfStmt).getCondition()=target_9
		and target_10.getEnclosingFunction() = func
}

*/
/*predicate func_11(RelationalOperation target_9, Function func, ExprStmt target_11) {
		target_11.getExpr() instanceof FunctionCall
		and target_11.getParent().(IfStmt).getCondition()=target_9
		and target_11.getEnclosingFunction() = func
}

*/
predicate func_12(Variable vcc_257, Variable vnpixels_259, BlockStmt target_18, RelationalOperation target_12) {
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getGreaterOperand().(VariableAccess).getTarget()=vcc_257
		and target_12.getLesserOperand().(Literal).getValue()="0"
		and target_12.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_12.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnpixels_259
		and target_12.getParent().(LogicalAndExpr).getParent().(ForStmt).getStmt()=target_18
}

predicate func_13(Variable vsp_256, EqualityOperation target_13) {
		target_13.getAnOperand().(PointerFieldAccess).getTarget().getName()="user_datafmt"
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_256
		and target_13.getAnOperand().(Literal).getValue()="2"
}

predicate func_14(Variable vsp_256, Variable vnpixels_259, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnpixels_259
		and target_14.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_14.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="pixel_size"
		and target_14.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_256
}

predicate func_15(Parameter vtif_253, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_15.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="tif_rawcp"
		and target_15.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_253
}

predicate func_16(Variable vsp_256, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32 *")
		and target_16.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="tbuf"
		and target_16.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_256
}

predicate func_17(Variable vnpixels_259, LogicalAndExpr target_17) {
		target_17.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_17.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnpixels_259
		and target_17.getAnOperand() instanceof RelationalOperation
}

predicate func_18(BlockStmt target_18) {
		target_18.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("uint32 *")
		and target_18.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_18.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_18.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_18.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_18.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
}

from Function func, Parameter vtif_253, Variable vsp_256, Variable vcc_257, Variable vnpixels_259, Variable v__PRETTY_FUNCTION__, FunctionCall target_0, PointerFieldAccess target_5, VariableAccess target_7, CommaExpr target_8, RelationalOperation target_12, EqualityOperation target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, LogicalAndExpr target_17, BlockStmt target_18
where
func_0(v__PRETTY_FUNCTION__, target_0)
and not func_1(vsp_256, vnpixels_259, target_13, target_14)
and not func_2(vtif_253, target_15)
and func_5(vsp_256, vnpixels_259, target_5)
and func_7(vcc_257, target_7)
and func_8(vsp_256, vnpixels_259, target_8)
and func_12(vcc_257, vnpixels_259, target_18, target_12)
and func_13(vsp_256, target_13)
and func_14(vsp_256, vnpixels_259, target_14)
and func_15(vtif_253, target_15)
and func_16(vsp_256, target_16)
and func_17(vnpixels_259, target_17)
and func_18(target_18)
and vtif_253.getType().hasName("TIFF *")
and vsp_256.getType().hasName("LogLuvState *")
and vcc_257.getType().hasName("tmsize_t")
and vnpixels_259.getType().hasName("tmsize_t")
and v__PRETTY_FUNCTION__.getType() instanceof ArrayType
and vtif_253.getFunction() = func
and vsp_256.(LocalVariable).getFunction() = func
and vcc_257.(LocalVariable).getFunction() = func
and vnpixels_259.(LocalVariable).getFunction() = func
and not v__PRETTY_FUNCTION__.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
