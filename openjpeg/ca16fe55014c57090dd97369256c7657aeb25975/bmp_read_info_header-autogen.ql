/**
 * @name openjpeg-ca16fe55014c57090dd97369256c7657aeb25975-bmp_read_info_header
 * @id cpp/openjpeg/ca16fe55014c57090dd97369256c7657aeb25975/bmp-read-info-header
 * @description openjpeg-ca16fe55014c57090dd97369256c7657aeb25975-src/bin/jp2/convertbmp.c-bmp_read_info_header CVE-2018-5785
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vheader_357, Variable vstderr, RelationalOperation target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="biRedMask"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Error, invalid red mask value %d\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="biRedMask"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vheader_357, Variable vstderr, RelationalOperation target_3, ExprStmt target_7, ExprStmt target_8) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="biGreenMask"
		and target_1.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Error, invalid green mask value %d\n"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="biGreenMask"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(9)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_7.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vheader_357, Variable vstderr, RelationalOperation target_3, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="biBlueMask"
		and target_2.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Error, invalid blue mask value %d\n"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="biBlueMask"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(14)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_9.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vheader_357, RelationalOperation target_3) {
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="biSize"
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_3.getLesserOperand().(Literal).getValue()="56"
}

predicate func_4(Parameter vheader_357, ExprStmt target_4) {
		target_4.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="biRedMask"
		and target_4.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_4.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getTarget().hasName("getc")
		and target_4.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
}

predicate func_5(Parameter vheader_357, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="biGreenMask"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("getc")
}

predicate func_6(Variable vstderr, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_6.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Error, invalid biBitCount %d\n"
		and target_6.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_7(Parameter vheader_357, ExprStmt target_7) {
		target_7.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="biGreenMask"
		and target_7.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_7.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getTarget().hasName("getc")
		and target_7.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
}

predicate func_8(Parameter vheader_357, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="biBlueMask"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("getc")
}

predicate func_9(Parameter vheader_357, ExprStmt target_9) {
		target_9.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="biBlueMask"
		and target_9.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_9.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getTarget().hasName("getc")
		and target_9.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
}

predicate func_10(Parameter vheader_357, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="biAlphaMask"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("getc")
}

predicate func_11(Variable vstderr, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_11.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Error, can't  read BMP header\n"
}

from Function func, Parameter vheader_357, Variable vstderr, RelationalOperation target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11
where
not func_0(vheader_357, vstderr, target_3, target_4, target_5, target_6)
and not func_1(vheader_357, vstderr, target_3, target_7, target_8)
and not func_2(vheader_357, vstderr, target_3, target_9, target_10, target_11)
and func_3(vheader_357, target_3)
and func_4(vheader_357, target_4)
and func_5(vheader_357, target_5)
and func_6(vstderr, target_6)
and func_7(vheader_357, target_7)
and func_8(vheader_357, target_8)
and func_9(vheader_357, target_9)
and func_10(vheader_357, target_10)
and func_11(vstderr, target_11)
and vheader_357.getType().hasName("OPJ_BITMAPINFOHEADER *")
and vstderr.getType().hasName("FILE *")
and vheader_357.getParentScope+() = func
and not vstderr.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
