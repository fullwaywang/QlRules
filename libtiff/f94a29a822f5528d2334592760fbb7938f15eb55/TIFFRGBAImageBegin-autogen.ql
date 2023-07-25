/**
 * @name libtiff-f94a29a822f5528d2334592760fbb7938f15eb55-TIFFRGBAImageBegin
 * @id cpp/libtiff/f94a29a822f5528d2334592760fbb7938f15eb55/TIFFRGBAImageBegin
 * @description libtiff-f94a29a822f5528d2334592760fbb7938f15eb55-libtiff/tif_getimage.c-TIFFRGBAImageBegin CVE-2015-8683
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtif_249, Parameter vemsg_249, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("TIFFRGBAImageOK")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_249
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vemsg_249
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0)
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtif_249, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tif"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TIFFRGBAImage *")
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtif_249
}

predicate func_2(Parameter vemsg_249, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("sprintf")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vemsg_249
		and target_2.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Sorry, can not handle images with %d-bit samples"
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="bitspersample"
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TIFFRGBAImage *")
}

from Function func, Parameter vtif_249, Parameter vemsg_249, ExprStmt target_1, ExprStmt target_2
where
not func_0(vtif_249, vemsg_249, target_1, target_2, func)
and func_1(vtif_249, target_1)
and func_2(vemsg_249, target_2)
and vtif_249.getType().hasName("TIFF *")
and vemsg_249.getType().hasName("char[1024]")
and vtif_249.getFunction() = func
and vemsg_249.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
