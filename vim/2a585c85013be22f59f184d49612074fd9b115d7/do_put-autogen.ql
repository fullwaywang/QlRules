/**
 * @name vim-2a585c85013be22f59f184d49612074fd9b115d7-do_put
 * @id cpp/vim/2a585c85013be22f59f184d49612074fd9b115d7/do-put
 * @description vim-2a585c85013be22f59f184d49612074fd9b115d7-src/register.c-do_put CVE-2022-1886
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcurbuf, RelationalOperation target_6, ExprStmt target_7) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_op_end"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_0.getExpr().(AssignExpr).getRValue() instanceof SubExpr
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcurbuf, Variable vlen_2100, RelationalOperation target_6, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, PointerArithmeticOperation target_11) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_2100
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getThen().(ExprStmt).getExpr().(AssignSubExpr).getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_1.getThen().(ExprStmt).getExpr().(AssignSubExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_op_end"
		and target_1.getThen().(ExprStmt).getExpr().(AssignSubExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_1.getThen().(ExprStmt).getExpr().(AssignSubExpr).getRValue() instanceof VariableCall
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getThen().(ExprStmt).getExpr().(AssignSubExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getThen().(ExprStmt).getExpr().(AssignSubExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_10.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_11.getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vcurbuf, ExprStmt target_8, ExprStmt target_9) {
	exists(AssignSubExpr target_2 |
		target_2.getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_2.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_op_end"
		and target_2.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_2.getRValue() instanceof VariableCall
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_3(Variable vcol_1537, SubExpr target_3) {
		target_3.getLeftOperand().(VariableAccess).getTarget()=vcol_1537
		and target_3.getRightOperand().(Literal).getValue()="1"
}

predicate func_4(Variable vmb_head_off, Variable vy_size_1540, Variable vy_array_1548, Variable vlen_2100, VariableCall target_4) {
		target_4.getExpr().(VariableAccess).getTarget()=vmb_head_off
		and target_4.getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vy_array_1548
		and target_4.getArgument(0).(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vy_size_1540
		and target_4.getArgument(0).(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_4.getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vy_array_1548
		and target_4.getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vy_size_1540
		and target_4.getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_4.getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen_2100
		and target_4.getArgument(1).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
}

predicate func_5(Variable vcurbuf, SubExpr target_5) {
		target_5.getLeftOperand() instanceof SubExpr
		and target_5.getRightOperand() instanceof VariableCall
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_5.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_op_end"
		and target_5.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
}

predicate func_6(Variable vcol_1537, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getGreaterOperand().(VariableAccess).getTarget()=vcol_1537
		and target_6.getLesserOperand().(Literal).getValue()="1"
}

predicate func_7(Variable vcurbuf, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_op_end"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_8(Variable vcurbuf, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_op_end"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
}

predicate func_9(Variable vcurbuf, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_op_end"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_9.getExpr().(AssignExpr).getRValue() instanceof SubExpr
}

predicate func_10(Variable vcol_1537, Variable vlen_2100, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcol_1537
		and target_10.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_2100
}

predicate func_11(Variable vy_size_1540, Variable vy_array_1548, Variable vlen_2100, PointerArithmeticOperation target_11) {
		target_11.getLeftOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vy_array_1548
		and target_11.getLeftOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vy_size_1540
		and target_11.getLeftOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_11.getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen_2100
		and target_11.getRightOperand().(Literal).getValue()="1"
}

from Function func, Variable vmb_head_off, Variable vcol_1537, Variable vy_size_1540, Variable vy_array_1548, Variable vcurbuf, Variable vlen_2100, SubExpr target_3, VariableCall target_4, SubExpr target_5, RelationalOperation target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, PointerArithmeticOperation target_11
where
not func_0(vcurbuf, target_6, target_7)
and not func_1(vcurbuf, vlen_2100, target_6, target_8, target_9, target_10, target_11)
and func_3(vcol_1537, target_3)
and func_4(vmb_head_off, vy_size_1540, vy_array_1548, vlen_2100, target_4)
and func_5(vcurbuf, target_5)
and func_6(vcol_1537, target_6)
and func_7(vcurbuf, target_7)
and func_8(vcurbuf, target_8)
and func_9(vcurbuf, target_9)
and func_10(vcol_1537, vlen_2100, target_10)
and func_11(vy_size_1540, vy_array_1548, vlen_2100, target_11)
and vmb_head_off.getType().hasName("..(*)(..)")
and vcol_1537.getType().hasName("colnr_T")
and vy_size_1540.getType().hasName("long")
and vy_array_1548.getType().hasName("char_u **")
and vcurbuf.getType().hasName("buf_T *")
and vlen_2100.getType().hasName("size_t")
and not vmb_head_off.getParentScope+() = func
and vcol_1537.getParentScope+() = func
and vy_size_1540.getParentScope+() = func
and vy_array_1548.getParentScope+() = func
and not vcurbuf.getParentScope+() = func
and vlen_2100.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
