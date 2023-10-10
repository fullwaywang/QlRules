/**
 * @name vim-395bd1f6d3edc9f7edb5d1f2d7deaf5a9e3ab93c-get_visual_text
 * @id cpp/vim/395bd1f6d3edc9f7edb5d1f2d7deaf5a9e3ab93c/get-visual-text
 * @description vim-395bd1f6d3edc9f7edb5d1f2d7deaf5a9e3ab93c-src/normal.c-get_visual_text CVE-2022-1720
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vhas_mbyte, Variable vmb_ptr2len, Parameter vpp_3644, Parameter vlenp_3645, LogicalAndExpr target_3, EqualityOperation target_4, PointerArithmeticOperation target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vhas_mbyte
		and target_0.getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlenp_3645
		and target_0.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vmb_ptr2len
		and target_0.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpp_3644
		and target_0.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlenp_3645
		and target_0.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignSubExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlenp_3645
		and target_0.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

/*predicate func_1(Variable vhas_mbyte, Parameter vlenp_3645, ExprStmt target_6, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlenp_3645
		and target_1.getLesserOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vhas_mbyte
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_6
}

*/
/*predicate func_2(Variable vhas_mbyte, Parameter vlenp_3645, ExprStmt target_6, VariableAccess target_2) {
		target_2.getTarget()=vhas_mbyte
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlenp_3645
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_6
}

*/
predicate func_3(Variable vhas_mbyte, ExprStmt target_6, LogicalAndExpr target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vhas_mbyte
		and target_3.getAnOperand() instanceof RelationalOperation
		and target_3.getParent().(IfStmt).getThen()=target_6
}

predicate func_4(Parameter vpp_3644, EqualityOperation target_4) {
		target_4.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpp_3644
		and target_4.getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Parameter vpp_3644, Parameter vlenp_3645, PointerArithmeticOperation target_5) {
		target_5.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpp_3644
		and target_5.getAnOperand().(SubExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlenp_3645
		and target_5.getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_6(Variable vmb_ptr2len, Parameter vpp_3644, Parameter vlenp_3645, ExprStmt target_6) {
		target_6.getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlenp_3645
		and target_6.getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vmb_ptr2len
		and target_6.getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(ExprCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpp_3644
		and target_6.getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(ExprCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_6.getExpr().(AssignAddExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

from Function func, Variable vhas_mbyte, Variable vmb_ptr2len, Parameter vpp_3644, Parameter vlenp_3645, LogicalAndExpr target_3, EqualityOperation target_4, PointerArithmeticOperation target_5, ExprStmt target_6
where
not func_0(vhas_mbyte, vmb_ptr2len, vpp_3644, vlenp_3645, target_3, target_4, target_5, target_6)
and func_3(vhas_mbyte, target_6, target_3)
and func_4(vpp_3644, target_4)
and func_5(vpp_3644, vlenp_3645, target_5)
and func_6(vmb_ptr2len, vpp_3644, vlenp_3645, target_6)
and vhas_mbyte.getType().hasName("int")
and vmb_ptr2len.getType().hasName("..(*)(..)")
and vpp_3644.getType().hasName("char_u **")
and vlenp_3645.getType().hasName("int *")
and not vhas_mbyte.getParentScope+() = func
and not vmb_ptr2len.getParentScope+() = func
and vpp_3644.getParentScope+() = func
and vlenp_3645.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
