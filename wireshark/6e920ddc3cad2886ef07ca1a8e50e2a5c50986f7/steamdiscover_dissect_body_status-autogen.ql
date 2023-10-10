/**
 * @name wireshark-6e920ddc3cad2886ef07ca1a8e50e2a5c50986f7-steamdiscover_dissect_body_status
 * @id cpp/wireshark/6e920ddc3cad2886ef07ca1a8e50e2a5c50986f7/steamdiscover-dissect-body-status
 * @description wireshark-6e920ddc3cad2886ef07ca1a8e50e2a5c50986f7-epan/dissectors/packet-steam-ihs-discovery.c-steamdiscover_dissect_body_status CVE-2018-18226
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
		target_0.getTarget().hasName("wmem_allocator_new")
		and not target_0.getTarget().hasName("wmem_packet_scope")
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, DeclStmt target_1) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vstrpool_494, Function func, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstrpool_494
		and target_2.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vstrpool_494, ExprStmt target_2, ExprStmt target_4, VariableAccess target_3) {
		target_3.getTarget()=vstrpool_494
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_get_string_enc")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="tvb"
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="offset"
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="2"
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getLocation())
		and target_3.getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_4(Variable vstrpool_494, Function func, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("wmem_destroy_allocator")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstrpool_494
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

from Function func, Variable vstrpool_494, FunctionCall target_0, DeclStmt target_1, ExprStmt target_2, VariableAccess target_3, ExprStmt target_4
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(vstrpool_494, func, target_2)
and func_3(vstrpool_494, target_2, target_4, target_3)
and func_4(vstrpool_494, func, target_4)
and vstrpool_494.getType().hasName("wmem_allocator_t *")
and vstrpool_494.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
