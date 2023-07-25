/**
 * @name libtiff-47f2fb61a3a64667bce1a8398a8fcb1b348ff122-JPEGSetupEncode
 * @id cpp/libtiff/47f2fb61a3a64667bce1a8398a8fcb1b348ff122/JPEGSetupEncode
 * @description libtiff-47f2fb61a3a64667bce1a8398a8fcb1b348ff122-libtiff/tif_jpeg.c-JPEGSetupEncode CVE-2017-7595
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsp_1579, Variable vmodule_1581, Parameter vtif_1577, PointerFieldAccess target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, NotExpr target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="h_sampling"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1579
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="v_sampling"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1579
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_1577
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_1581
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalig horizontal/vertical sampling value"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vsp_1579, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="photometric"
		and target_1.getQualifier().(VariableAccess).getTarget()=vsp_1579
}

predicate func_2(Variable vsp_1579, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="v_sampling"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1579
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="td_ycbcrsubsampling"
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TIFFDirectory *")
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_3(Variable vsp_1579, Variable vmodule_1581, Parameter vtif_1577, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_1577
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_1581
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="PhotometricInterpretation %d not allowed for JPEG"
		and target_3.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="photometric"
		and target_3.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1579
}

predicate func_4(Parameter vtif_1577, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("JPEGInitializeLibJPEG")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_1577
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_5(Parameter vtif_1577, NotExpr target_5) {
		target_5.getOperand().(FunctionCall).getTarget().hasName("TIFFGetField")
		and target_5.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_1577
		and target_5.getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="532"
		and target_5.getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("float *")
}

from Function func, Variable vsp_1579, Variable vmodule_1581, Parameter vtif_1577, PointerFieldAccess target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, NotExpr target_5
where
not func_0(vsp_1579, vmodule_1581, vtif_1577, target_1, target_2, target_3, target_4, target_5)
and func_1(vsp_1579, target_1)
and func_2(vsp_1579, target_2)
and func_3(vsp_1579, vmodule_1581, vtif_1577, target_3)
and func_4(vtif_1577, target_4)
and func_5(vtif_1577, target_5)
and vsp_1579.getType().hasName("JPEGState *")
and vmodule_1581.getType().hasName("const char[]")
and vtif_1577.getType().hasName("TIFF *")
and vsp_1579.(LocalVariable).getFunction() = func
and vmodule_1581.(LocalVariable).getFunction() = func
and vtif_1577.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
