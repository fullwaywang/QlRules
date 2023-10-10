/**
 * @name openjpeg-c22cbd8bdf8ff2ae372f94391a4be2d322b36b41-pnmtoimage
 * @id cpp/openjpeg/c22cbd8bdf8ff2ae372f94391a4be2d322b36b41/pnmtoimage
 * @description openjpeg-c22cbd8bdf8ff2ae372f94391a4be2d322b36b41-src/bin/jp2/convert.c-pnmtoimage CVE-2016-9118
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vheader_info_1719, Variable vstderr, NotExpr target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="height"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_info_1719
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="width"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_info_1719
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="height"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_info_1719
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="pnmtoimage:Image %dx%d too big!\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="width"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_info_1719
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="height"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_info_1719
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_0)
		and target_3.getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vfp_1714, NotExpr target_7, ExprStmt target_2, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfp_1714
		and (func.getEntryPoint().(BlockStmt).getStmt(31)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(31).getFollowingStmt()=target_1)
		and target_7.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vfp_1714, Function func, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfp_1714
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vheader_info_1719, NotExpr target_3) {
		target_3.getOperand().(ValueFieldAccess).getTarget().getName()="ok"
		and target_3.getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_info_1719
}

predicate func_4(Variable vheader_info_1719, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="format"
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_info_1719
}

predicate func_5(Variable vstderr, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_5.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="pnmtoimage:Failed to open %s for reading!\n"
}

predicate func_6(Variable vstderr, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_6.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\nWARNING: fscanf return a number of element different from the expected.\n"
}

predicate func_7(Variable vfp_1714, NotExpr target_7) {
		target_7.getOperand().(FunctionCall).getTarget().hasName("fread")
		and target_7.getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_7.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_7.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vfp_1714
}

from Function func, Variable vfp_1714, Variable vheader_info_1719, Variable vstderr, ExprStmt target_2, NotExpr target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, NotExpr target_7
where
not func_0(vheader_info_1719, vstderr, target_3, target_4, target_5, target_6, func)
and not func_1(vfp_1714, target_7, target_2, func)
and func_2(vfp_1714, func, target_2)
and func_3(vheader_info_1719, target_3)
and func_4(vheader_info_1719, target_4)
and func_5(vstderr, target_5)
and func_6(vstderr, target_6)
and func_7(vfp_1714, target_7)
and vfp_1714.getType().hasName("FILE *")
and vheader_info_1719.getType().hasName("pnm_header")
and vstderr.getType().hasName("FILE *")
and vfp_1714.getParentScope+() = func
and vheader_info_1719.getParentScope+() = func
and not vstderr.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
