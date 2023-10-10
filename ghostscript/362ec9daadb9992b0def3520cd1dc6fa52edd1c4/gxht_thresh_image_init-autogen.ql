/**
 * @name ghostscript-362ec9daadb9992b0def3520cd1dc6fa52edd1c4-gxht_thresh_image_init
 * @id cpp/ghostscript/362ec9daadb9992b0def3520cd1dc6fa52edd1c4/gxht-thresh-image-init
 * @description ghostscript-362ec9daadb9992b0def3520cd1dc6fa52edd1c4-base/gxht_thresh.c-gxht_thresh_image_init CVE-2016-10317
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmax_height_581, ReturnStmt target_9) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vmax_height_581
		and target_0.getGreaterOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen()=target_9)
}

predicate func_1(EqualityOperation target_10, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition() instanceof RelationalOperation
		and target_1.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(9)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vpenum_576, Variable vmax_height_581, EqualityOperation target_10, DivExpr target_11, ExprStmt target_12, ExprStmt target_13, LogicalAndExpr target_8) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="line_size"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpenum_576
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(ComplementExpr).getValue()="2147483647"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vmax_height_581
		and target_2.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_2.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ht_buffer"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpenum_576
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(14)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_11.getLeftOperand().(MulExpr).getLeftOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vpenum_576, DivExpr target_11, LogicalAndExpr target_8) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="line_size"
		and target_3.getQualifier().(VariableAccess).getTarget()=vpenum_576
		and target_11.getLeftOperand().(MulExpr).getLeftOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_4(Variable vmax_height_581, ExprStmt target_13, LogicalAndExpr target_8) {
	exists(DivExpr target_4 |
		target_4.getLeftOperand().(ComplementExpr).getValue()="2147483647"
		and target_4.getRightOperand().(VariableAccess).getTarget()=vmax_height_581
		and target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getRightOperand().(VariableAccess).getLocation())
		and target_4.getRightOperand().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

*/
predicate func_5(Parameter vpenum_576, Variable vmax_height_581, Variable vspp_out_582, ReturnStmt target_9, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="ht_stride"
		and target_5.getGreaterOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpenum_576
		and target_5.getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vspp_out_582
		and target_5.getLesserOperand().(DivExpr).getLeftOperand().(ComplementExpr).getValue()="2147483647"
		and target_5.getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vmax_height_581
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmax_height_581
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_5.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_9
}

/*predicate func_6(Variable vmax_height_581, VariableAccess target_6) {
		target_6.getTarget()=vmax_height_581
}

*/
predicate func_8(Variable vmax_height_581, ReturnStmt target_9, LogicalAndExpr target_8) {
		target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmax_height_581
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_8.getAnOperand() instanceof RelationalOperation
		and target_8.getParent().(IfStmt).getThen()=target_9
}

predicate func_9(ReturnStmt target_9) {
		target_9.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_10(Parameter vpenum_576, EqualityOperation target_10) {
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="posture"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpenum_576
}

predicate func_11(Parameter vpenum_576, DivExpr target_11) {
		target_11.getLeftOperand().(MulExpr).getLeftOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="dst_height"
		and target_11.getLeftOperand().(MulExpr).getLeftOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpenum_576
		and target_11.getLeftOperand().(MulExpr).getLeftOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_11.getLeftOperand().(MulExpr).getLeftOperand().(ConditionalExpr).getThen().(UnaryMinusExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dst_height"
		and target_11.getLeftOperand().(MulExpr).getLeftOperand().(ConditionalExpr).getThen().(UnaryMinusExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpenum_576
		and target_11.getLeftOperand().(MulExpr).getLeftOperand().(ConditionalExpr).getElse().(PointerFieldAccess).getTarget().getName()="dst_height"
		and target_11.getLeftOperand().(MulExpr).getLeftOperand().(ConditionalExpr).getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpenum_576
		and target_11.getLeftOperand().(MulExpr).getRightOperand().(DivExpr).getValue()="0.00390625"
		and target_11.getRightOperand().(PointerFieldAccess).getTarget().getName()="Height"
		and target_11.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpenum_576
}

predicate func_12(Parameter vpenum_576, Variable vspp_out_582, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="line"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpenum_576
		and target_12.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="alloc_bytes"
		and target_12.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_12.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_12.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="memory"
		and target_12.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpenum_576
		and target_12.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="line_size"
		and target_12.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpenum_576
		and target_12.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vspp_out_582
		and target_12.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(StringLiteral).getValue()="gxht_thresh"
}

predicate func_13(Parameter vpenum_576, Variable vmax_height_581, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmax_height_581
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ceil")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(DivExpr).getLeftOperand().(MulExpr).getLeftOperand().(ConditionalExpr).getElse().(PointerFieldAccess).getTarget().getName()="dst_height"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(DivExpr).getLeftOperand().(MulExpr).getRightOperand().(DivExpr).getValue()="0.00390625"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(DivExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="Height"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(DivExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpenum_576
}

from Function func, Parameter vpenum_576, Variable vmax_height_581, Variable vspp_out_582, RelationalOperation target_5, LogicalAndExpr target_8, ReturnStmt target_9, EqualityOperation target_10, DivExpr target_11, ExprStmt target_12, ExprStmt target_13
where
not func_0(vmax_height_581, target_9)
and not func_1(target_10, func)
and not func_2(vpenum_576, vmax_height_581, target_10, target_11, target_12, target_13, target_8)
and func_5(vpenum_576, vmax_height_581, vspp_out_582, target_9, target_5)
and func_8(vmax_height_581, target_9, target_8)
and func_9(target_9)
and func_10(vpenum_576, target_10)
and func_11(vpenum_576, target_11)
and func_12(vpenum_576, vspp_out_582, target_12)
and func_13(vpenum_576, vmax_height_581, target_13)
and vpenum_576.getType().hasName("gx_image_enum *")
and vmax_height_581.getType().hasName("int")
and vspp_out_582.getType().hasName("int")
and vpenum_576.getFunction() = func
and vmax_height_581.(LocalVariable).getFunction() = func
and vspp_out_582.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
