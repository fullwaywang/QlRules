/**
 * @name imagemagick-17a1a6f97fd088a71931bdc422f4e96bb6ffc549-ParseImageResourceBlocks
 * @id cpp/imagemagick/17a1a6f97fd088a71931bdc422f4e96bb6ffc549/ParseImageResourceBlocks
 * @description imagemagick-17a1a6f97fd088a71931bdc422f4e96bb6ffc549-coders/psd.c-ParseImageResourceBlocks CVE-2018-16413
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vblocks_756, Variable vp_760, Variable vcount_769, BreakStmt target_2, RelationalOperation target_3, RelationalOperation target_1, ExprStmt target_4, AddressOfExpr target_5) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_760
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vcount_769
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vblocks_756
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vblocks_756, Parameter vlength_756, Variable vp_760, Variable vcount_769, BreakStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_760
		and target_1.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vcount_769
		and target_1.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vblocks_756
		and target_1.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlength_756
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BreakStmt target_2) {
		target_2.toString() = "break;"
}

predicate func_3(Parameter vblocks_756, Parameter vlength_756, Variable vp_760, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vp_760
		and target_3.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vblocks_756
		and target_3.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlength_756
		and target_3.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="4"
}

predicate func_4(Variable vp_760, Variable vcount_769, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_760
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("PushLongPixel")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_760
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcount_769
}

predicate func_5(Variable vcount_769, AddressOfExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vcount_769
}

from Function func, Parameter vblocks_756, Parameter vlength_756, Variable vp_760, Variable vcount_769, RelationalOperation target_1, BreakStmt target_2, RelationalOperation target_3, ExprStmt target_4, AddressOfExpr target_5
where
not func_0(vblocks_756, vp_760, vcount_769, target_2, target_3, target_1, target_4, target_5)
and func_1(vblocks_756, vlength_756, vp_760, vcount_769, target_2, target_1)
and func_2(target_2)
and func_3(vblocks_756, vlength_756, vp_760, target_3)
and func_4(vp_760, vcount_769, target_4)
and func_5(vcount_769, target_5)
and vblocks_756.getType().hasName("const unsigned char *")
and vlength_756.getType().hasName("size_t")
and vp_760.getType().hasName("const unsigned char *")
and vcount_769.getType().hasName("unsigned int")
and vblocks_756.getParentScope+() = func
and vlength_756.getParentScope+() = func
and vp_760.getParentScope+() = func
and vcount_769.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
