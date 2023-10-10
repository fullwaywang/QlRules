/**
 * @name imagemagick-8a43abefb38c5e29138e1c9c515b313363541c06-WritePSDChannel
 * @id cpp/imagemagick/8a43abefb38c5e29138e1c9c515b313363541c06/WritePSDChannel
 * @description imagemagick-8a43abefb38c5e29138e1c9c515b313363541c06-coders/psd.c-WritePSDChannel CVE-2019-7395
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcompressed_pixels_2745, EqualityOperation target_1, EqualityOperation target_2, ExprStmt target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcompressed_pixels_2745
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcompressed_pixels_2745
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_1) {
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("deflateInit_")
		and target_1.getAnOperand().(FunctionCall).getArgument(2).(StringLiteral).getValue()="1.2.11"
		and target_1.getAnOperand().(FunctionCall).getArgument(3).(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getAnOperand().(FunctionCall).getArgument(3).(SizeofTypeOperator).getValue()="112"
		and target_1.getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Variable vcompressed_pixels_2745, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vcompressed_pixels_2745
		and target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Variable vcompressed_pixels_2745, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="next_out"
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcompressed_pixels_2745
}

from Function func, Variable vcompressed_pixels_2745, EqualityOperation target_1, EqualityOperation target_2, ExprStmt target_3
where
not func_0(vcompressed_pixels_2745, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vcompressed_pixels_2745, target_2)
and func_3(vcompressed_pixels_2745, target_3)
and vcompressed_pixels_2745.getType().hasName("unsigned char *")
and vcompressed_pixels_2745.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
