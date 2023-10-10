/**
 * @name openjpeg-2cd30c2b06ce332dede81cccad8b334cde997281-tgatoimage
 * @id cpp/openjpeg/2cd30c2b06ce332dede81cccad8b334cde997281/tgatoimage
 * @description openjpeg-2cd30c2b06ce332dede81cccad8b334cde997281-src/bin/jp2/convert.c-tgatoimage CVE-2017-14040
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vf_773, Variable vimage_width_775, Variable vimage_height_775, Variable vnumcomps_779, ExprStmt target_3, AddressOfExpr target_4, AddressOfExpr target_5, ExprStmt target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage_height_775
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vimage_width_775
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(DivExpr).getLeftOperand().(Literal).getValue()="10000000"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vimage_height_775
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vnumcomps_779
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("OPJ_UINT64")
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("OPJ_UINT64")
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2147483647"
		and target_0.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fseek")
		and target_0.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vf_773
		and target_0.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(VariableAccess).getType().hasName("OPJ_UINT64")
		and target_0.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("fread")
		and target_0.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("char")
		and target_0.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vf_773
		and target_0.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fseek")
		and target_0.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vf_773
		and target_0.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("long")
		and target_0.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_0)
		and target_0.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vf_773, ExprStmt target_7, ExprStmt target_2, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vf_773
		and (func.getEntryPoint().(BlockStmt).getStmt(31)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(31).getFollowingStmt()=target_1)
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vf_773, Function func, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vf_773
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vf_773, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vf_773
}

predicate func_4(Variable vimage_width_775, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vimage_width_775
}

predicate func_5(Variable vimage_height_775, AddressOfExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vimage_height_775
}

predicate func_6(Variable vnumcomps_779, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnumcomps_779
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="4"
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="3"
}

predicate func_7(Variable vf_773, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vf_773
}

from Function func, Variable vf_773, Variable vimage_width_775, Variable vimage_height_775, Variable vnumcomps_779, ExprStmt target_2, ExprStmt target_3, AddressOfExpr target_4, AddressOfExpr target_5, ExprStmt target_6, ExprStmt target_7
where
not func_0(vf_773, vimage_width_775, vimage_height_775, vnumcomps_779, target_3, target_4, target_5, target_6, func)
and not func_1(vf_773, target_7, target_2, func)
and func_2(vf_773, func, target_2)
and func_3(vf_773, target_3)
and func_4(vimage_width_775, target_4)
and func_5(vimage_height_775, target_5)
and func_6(vnumcomps_779, target_6)
and func_7(vf_773, target_7)
and vf_773.getType().hasName("FILE *")
and vimage_width_775.getType().hasName("unsigned int")
and vimage_height_775.getType().hasName("unsigned int")
and vnumcomps_779.getType().hasName("int")
and vf_773.getParentScope+() = func
and vimage_width_775.getParentScope+() = func
and vimage_height_775.getParentScope+() = func
and vnumcomps_779.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
