/**
 * @name vim-c249913edc35c0e666d783bfc21595cf9f7d9e0d-op_replace
 * @id cpp/vim/c249913edc35c0e666d783bfc21595cf9f7d9e0d/op-replace
 * @description vim-c249913edc35c0e666d783bfc21595cf9f7d9e0d-src/ops.c-op_replace CVE-2022-3234
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(LogicalOrExpr target_7, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(BlockStmt target_8, Function func) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("gchar_cursor")
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_8
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(LogicalAndExpr target_9, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter voap_1019, Variable vcurwin, Variable vvirtual_op, Variable vvirtcols_1212, AddressOfExpr target_10, ExprStmt target_11, ExprStmt target_5, ValueFieldAccess target_12, LogicalAndExpr target_13) {
	exists(IfStmt target_3 |
		target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vvirtual_op
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="end"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voap_1019
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="coladd"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="start"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voap_1019
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vvirtcols_1212
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignSubExpr).getRValue().(ValueFieldAccess).getTarget().getName()="coladd"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignSubExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="start"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("coladvance_force")
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("getviscol2")
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="col"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="coladd"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vvirtcols_1212
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_3.getThen().(BlockStmt).getStmt(4).(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vvirtcols_1212
		and target_3.getThen().(BlockStmt).getStmt(4).(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(4).(BlockStmt).getStmt(0).(ForStmt).getUpdate().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vvirtcols_1212
		and target_3.getThen().(BlockStmt).getStmt(4).(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_3.getThen().(BlockStmt).getStmt(4).(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:"
		and target_10.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignSubExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_4(Parameter voap_1019, Variable vcurwin, Variable vvirtual_op, BlockStmt target_8, LogicalAndExpr target_13) {
	exists(LogicalAndExpr target_4 |
		target_4.getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_4.getAnOperand().(VariableAccess).getTarget()=vvirtual_op
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vvirtual_op
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="end"
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voap_1019
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_8
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_5(Parameter vc_1019, Variable vcurbuf, Variable vcurwin, LogicalOrExpr target_7, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getTarget().hasName("ml_get_buf")
		and target_5.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcurbuf
		and target_5.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="lnum"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vc_1019
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
}

predicate func_6(Parameter voap_1019, Variable vcurwin, Variable vvirtual_op, BlockStmt target_8, VariableAccess target_6) {
		target_6.getTarget()=vvirtual_op
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="end"
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voap_1019
		and target_6.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_8
}

predicate func_7(LogicalOrExpr target_7) {
		target_7.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_7.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
}

predicate func_8(Parameter voap_1019, Variable vvirtcols_1212, BlockStmt target_8) {
		target_8.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_8.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_8.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_8.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="start"
		and target_8.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_8.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="start"
		and target_8.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_8.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="end"
		and target_8.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="coladd"
		and target_8.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="start"
		and target_8.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voap_1019
		and target_8.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vvirtcols_1212
		and target_8.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignSubExpr).getRValue().(ValueFieldAccess).getTarget().getName()="coladd"
		and target_8.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignSubExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="start"
		and target_8.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignSubExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voap_1019
}

predicate func_9(Parameter voap_1019, Variable vcurwin, Variable vvirtual_op, LogicalAndExpr target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vvirtual_op
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="end"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voap_1019
}

predicate func_10(Parameter voap_1019, AddressOfExpr target_10) {
		target_10.getOperand().(PointerFieldAccess).getTarget().getName()="end"
		and target_10.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voap_1019
}

predicate func_11(Parameter voap_1019, Variable vvirtcols_1212, ExprStmt target_11) {
		target_11.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vvirtcols_1212
		and target_11.getExpr().(AssignSubExpr).getRValue().(ValueFieldAccess).getTarget().getName()="coladd"
		and target_11.getExpr().(AssignSubExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="start"
		and target_11.getExpr().(AssignSubExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voap_1019
}

predicate func_12(Variable vcurwin, ValueFieldAccess target_12) {
		target_12.getTarget().getName()="lnum"
		and target_12.getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_12.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
}

predicate func_13(Variable vvirtual_op, LogicalAndExpr target_13) {
		target_13.getAnOperand().(ValueFieldAccess).getTarget().getName()="is_short"
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vvirtual_op
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="is_MAX"
}

from Function func, Parameter voap_1019, Parameter vc_1019, Variable vcurbuf, Variable vcurwin, Variable vvirtual_op, Variable vvirtcols_1212, ExprStmt target_5, VariableAccess target_6, LogicalOrExpr target_7, BlockStmt target_8, LogicalAndExpr target_9, AddressOfExpr target_10, ExprStmt target_11, ValueFieldAccess target_12, LogicalAndExpr target_13
where
not func_0(target_7, func)
and not func_1(target_8, func)
and not func_2(target_9, func)
and not func_3(voap_1019, vcurwin, vvirtual_op, vvirtcols_1212, target_10, target_11, target_5, target_12, target_13)
and func_5(vc_1019, vcurbuf, vcurwin, target_7, target_5)
and func_6(voap_1019, vcurwin, vvirtual_op, target_8, target_6)
and func_7(target_7)
and func_8(voap_1019, vvirtcols_1212, target_8)
and func_9(voap_1019, vcurwin, vvirtual_op, target_9)
and func_10(voap_1019, target_10)
and func_11(voap_1019, vvirtcols_1212, target_11)
and func_12(vcurwin, target_12)
and func_13(vvirtual_op, target_13)
and voap_1019.getType().hasName("oparg_T *")
and vc_1019.getType().hasName("int")
and vcurbuf.getType().hasName("buf_T *")
and vcurwin.getType().hasName("win_T *")
and vvirtual_op.getType().hasName("int")
and vvirtcols_1212.getType().hasName("int")
and voap_1019.getParentScope+() = func
and vc_1019.getParentScope+() = func
and not vcurbuf.getParentScope+() = func
and not vcurwin.getParentScope+() = func
and not vvirtual_op.getParentScope+() = func
and vvirtcols_1212.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
