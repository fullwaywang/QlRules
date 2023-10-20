/**
 * @name libjpeg-turbo-9c78a04df4e44ef6487eee99c4258397f4fdca55-start_input_bmp
 * @id cpp/libjpeg-turbo/9c78a04df4e44ef6487eee99c4258397f4fdca55/start-input-bmp
 * @description libjpeg-turbo-9c78a04df4e44ef6487eee99c4258397f4fdca55-rdbmp.c-start_input_bmp CVE-2018-14498
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_5(Variable vsource_416, Variable vbiClrUsed_436, RelationalOperation target_6, ExprStmt target_7, ExprStmt target_8) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cmap_length"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_416
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbiClrUsed_436
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(Literal).getValue()="0"
}

predicate func_7(Variable vsource_416, Variable vbiClrUsed_436, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="colormap"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_416
		and target_7.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="alloc_sarray"
		and target_7.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mem"
		and target_7.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(Literal).getValue()="1"
		and target_7.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(VariableAccess).getTarget()=vbiClrUsed_436
		and target_7.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(3).(Literal).getValue()="3"
}

predicate func_8(Variable vsource_416, Variable vbiClrUsed_436, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("read_colormap")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsource_416
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbiClrUsed_436
}

from Function func, Variable vsource_416, Variable vbiClrUsed_436, RelationalOperation target_6, ExprStmt target_7, ExprStmt target_8
where
not func_5(vsource_416, vbiClrUsed_436, target_6, target_7, target_8)
and func_6(target_6)
and func_7(vsource_416, vbiClrUsed_436, target_7)
and func_8(vsource_416, vbiClrUsed_436, target_8)
and vsource_416.getType().hasName("bmp_source_ptr")
and vbiClrUsed_436.getType().hasName("unsigned int")
and vsource_416.getParentScope+() = func
and vbiClrUsed_436.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
