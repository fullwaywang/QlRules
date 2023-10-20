/**
 * @name openjpeg-da940424816e11d624362ce080bc026adffa26e8-bmptoimage
 * @id cpp/openjpeg/da940424816e11d624362ce080bc026adffa26e8/bmptoimage
 * @description openjpeg-da940424816e11d624362ce080bc026adffa26e8-src/bin/jp2/convertbmp.c-bmptoimage CVE-2016-10507
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vInfo_h_620, BlockStmt target_9, LogicalAndExpr target_6) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="biWidth"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vInfo_h_620
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="biHeight"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vInfo_h_620
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_9
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(LogicalAndExpr target_6, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vIN_618, Variable vInfo_h_620, ExprStmt target_10, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="biBitCount"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vInfo_h_620
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(SubExpr).getValue()="4294967264"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="biWidth"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vInfo_h_620
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vIN_618
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_2)
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Variable vIN_618, Variable vInfo_h_620, ExprStmt target_7, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition() instanceof LogicalAndExpr
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(SubExpr).getValue()="4294967264"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="biWidth"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vInfo_h_620
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vIN_618
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_3))
}

predicate func_4(Variable vIN_618, Variable vInfo_h_620, Variable vstride_624, ExprStmt target_12, MulExpr target_13, ExprStmt target_7, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vstride_624
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(DivExpr).getValue()="4294967295"
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="biHeight"
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vInfo_h_620
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vIN_618
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_4)
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getLeftOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vIN_618, ExprStmt target_14, ExprStmt target_8, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vIN_618
		and (func.getEntryPoint().(BlockStmt).getStmt(41)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(41).getFollowingStmt()=target_5)
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(Variable vInfo_h_620, BlockStmt target_9, LogicalAndExpr target_6) {
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="biBitCount"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vInfo_h_620
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="biCompression"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vInfo_h_620
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_6.getParent().(IfStmt).getThen()=target_9
}

predicate func_7(Variable vstride_624, LogicalAndExpr target_6, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstride_624
		and target_7.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="biWidth"
		and target_7.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="8"
		and target_7.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="31"
		and target_7.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(DivExpr).getRightOperand().(Literal).getValue()="32"
		and target_7.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="4"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_8(Variable vIN_618, Function func, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vIN_618
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(BlockStmt target_9) {
		target_9.getStmt(0) instanceof ExprStmt
}

predicate func_10(Variable vIN_618, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("getc")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vIN_618
}

predicate func_12(Variable vIN_618, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vIN_618
}

predicate func_13(Variable vInfo_h_620, Variable vstride_624, MulExpr target_13) {
		target_13.getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vstride_624
		and target_13.getLeftOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="biHeight"
		and target_13.getLeftOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vInfo_h_620
		and target_13.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_13.getRightOperand().(SizeofTypeOperator).getValue()="1"
}

predicate func_14(Variable vIN_618, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vIN_618
}

from Function func, Variable vIN_618, Variable vInfo_h_620, Variable vstride_624, LogicalAndExpr target_6, ExprStmt target_7, ExprStmt target_8, BlockStmt target_9, ExprStmt target_10, ExprStmt target_12, MulExpr target_13, ExprStmt target_14
where
not func_0(vInfo_h_620, target_9, target_6)
and not func_1(target_6, func)
and not func_2(vIN_618, vInfo_h_620, target_10, func)
and not func_3(vIN_618, vInfo_h_620, target_7, func)
and not func_4(vIN_618, vInfo_h_620, vstride_624, target_12, target_13, target_7, func)
and not func_5(vIN_618, target_14, target_8, func)
and func_6(vInfo_h_620, target_9, target_6)
and func_7(vstride_624, target_6, target_7)
and func_8(vIN_618, func, target_8)
and func_9(target_9)
and func_10(vIN_618, target_10)
and func_12(vIN_618, target_12)
and func_13(vInfo_h_620, vstride_624, target_13)
and func_14(vIN_618, target_14)
and vIN_618.getType().hasName("FILE *")
and vInfo_h_620.getType().hasName("OPJ_BITMAPINFOHEADER")
and vstride_624.getType().hasName("OPJ_UINT32")
and vIN_618.getParentScope+() = func
and vInfo_h_620.getParentScope+() = func
and vstride_624.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
