/**
 * @name imagemagick-d17c047f7bff7c0edbf304470cd2ab9d02fbf617-Magick_png_write_raw_profile
 * @id cpp/imagemagick/d17c047f7bff7c0edbf304470cd2ab9d02fbf617/Magick-png-write-raw-profile
 * @description imagemagick-d17c047f7bff7c0edbf304470cd2ab9d02fbf617-coders/png.c-Magick_png_write_raw_profile CVE-2019-19949
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlength_8162, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlength_8162
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vprofile_type_8161, Function func, IfStmt target_1) {
		target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("LocaleNCompare")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vprofile_type_8161
		and target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ng-chunk-"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="9"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(ReturnStmt).toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vprofile_type_8161, Parameter vlength_8162, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("printf")
		and target_2.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="writing raw profile: type=%s, length=%.20g\n"
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vprofile_type_8161
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlength_8162
}

from Function func, Parameter vprofile_type_8161, Parameter vlength_8162, IfStmt target_1, ExprStmt target_2
where
not func_0(vlength_8162, target_2, func)
and func_1(vprofile_type_8161, func, target_1)
and func_2(vprofile_type_8161, vlength_8162, target_2)
and vprofile_type_8161.getType().hasName("unsigned char *")
and vlength_8162.getType().hasName("png_uint_32")
and vprofile_type_8161.getParentScope+() = func
and vlength_8162.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
