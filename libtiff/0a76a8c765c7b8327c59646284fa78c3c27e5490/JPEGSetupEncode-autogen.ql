/**
 * @name libtiff-0a76a8c765c7b8327c59646284fa78c3c27e5490-JPEGSetupEncode
 * @id cpp/libtiff/0a76a8c765c7b8327c59646284fa78c3c27e5490/JPEGSetupEncode
 * @description libtiff-0a76a8c765c7b8327c59646284fa78c3c27e5490-libtiff/tif_jpeg.c-JPEGSetupEncode CVE-2017-7601
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtif_1577, Variable vtd_1580, Variable vmodule_1581, PointerFieldAccess target_1, ExprStmt target_2, NotExpr target_3, ExprStmt target_4, BinaryBitwiseOperation target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="td_bitspersample"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_1580
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_1577
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_1581
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="BitsPerSample %d not allowed for JPEG"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="td_bitspersample"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_1580
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_1
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(PointerFieldAccess target_1) {
		target_1.getTarget().getName()="photometric"
		and target_1.getQualifier().(VariableAccess).getTarget().getType().hasName("JPEGState *")
}

predicate func_2(Parameter vtif_1577, Variable vmodule_1581, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_1577
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_1581
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalig horizontal/vertical sampling value"
}

predicate func_3(Parameter vtif_1577, NotExpr target_3) {
		target_3.getOperand().(FunctionCall).getTarget().hasName("TIFFGetField")
		and target_3.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_1577
		and target_3.getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="532"
		and target_3.getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("float *")
}

predicate func_4(Variable vtd_1580, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="v_sampling"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("JPEGState *")
		and target_4.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="td_ycbcrsubsampling"
		and target_4.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_1580
		and target_4.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_5(Variable vtd_1580, BinaryBitwiseOperation target_5) {
		target_5.getLeftOperand().(Literal).getValue()="1"
		and target_5.getRightOperand().(PointerFieldAccess).getTarget().getName()="td_bitspersample"
		and target_5.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_1580
}

predicate func_6(Parameter vtif_1577, Variable vmodule_1581, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_1577
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_1581
		and target_6.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="PhotometricInterpretation %d not allowed for JPEG"
		and target_6.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="photometric"
		and target_6.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("JPEGState *")
}

from Function func, Parameter vtif_1577, Variable vtd_1580, Variable vmodule_1581, PointerFieldAccess target_1, ExprStmt target_2, NotExpr target_3, ExprStmt target_4, BinaryBitwiseOperation target_5, ExprStmt target_6
where
not func_0(vtif_1577, vtd_1580, vmodule_1581, target_1, target_2, target_3, target_4, target_5, target_6)
and func_1(target_1)
and func_2(vtif_1577, vmodule_1581, target_2)
and func_3(vtif_1577, target_3)
and func_4(vtd_1580, target_4)
and func_5(vtd_1580, target_5)
and func_6(vtif_1577, vmodule_1581, target_6)
and vtif_1577.getType().hasName("TIFF *")
and vtd_1580.getType().hasName("TIFFDirectory *")
and vmodule_1581.getType().hasName("const char[]")
and vtif_1577.getFunction() = func
and vtd_1580.(LocalVariable).getFunction() = func
and vmodule_1581.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
