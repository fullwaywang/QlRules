/**
 * @name openjpeg-baf0c1ad4572daa89caa3b12985bdd93530f0dd7-bmp_read_info_header
 * @id cpp/openjpeg/baf0c1ad4572daa89caa3b12985bdd93530f0dd7/bmp-read-info-header
 * @description openjpeg-baf0c1ad4572daa89caa3b12985bdd93530f0dd7-src/bin/jp2/convertbmp.c-bmp_read_info_header CVE-2017-12982
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vheader_357, Variable vstderr, ExprStmt target_1, RelationalOperation target_2, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="biBitCount"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Error, invalid biBitCount %d\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vheader_357, ExprStmt target_1) {
		target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="biBitCount"
		and target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_1.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getTarget().hasName("getc")
		and target_1.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
}

predicate func_2(Parameter vheader_357, RelationalOperation target_2) {
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="biSize"
		and target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
		and target_2.getLesserOperand().(Literal).getValue()="40"
}

predicate func_3(Parameter vheader_357, Variable vstderr, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_3.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Error, unknown BMP header size %d\n"
		and target_3.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="biSize"
		and target_3.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_357
}

predicate func_4(Variable vstderr, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_4.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Error, can't  read BMP header\n"
}

from Function func, Parameter vheader_357, Variable vstderr, ExprStmt target_1, RelationalOperation target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vheader_357, vstderr, target_1, target_2, target_3, target_4, func)
and func_1(vheader_357, target_1)
and func_2(vheader_357, target_2)
and func_3(vheader_357, vstderr, target_3)
and func_4(vstderr, target_4)
and vheader_357.getType().hasName("OPJ_BITMAPINFOHEADER *")
and vstderr.getType().hasName("FILE *")
and vheader_357.getParentScope+() = func
and not vstderr.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
