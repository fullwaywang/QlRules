/**
 * @name wireshark-53682b53da7f0d51effc042cc8613b47d2d65819-coherent_set_key_hash_by_key
 * @id cpp/wireshark/53682b53da7f0d51effc042cc8613b47d2d65819/coherent-set-key-hash-by-key
 * @description wireshark-53682b53da7f0d51effc042cc8613b47d2d65819-epan/dissectors/packet-rtps.c-coherent_set_key_hash_by_key CVE-2020-26420
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vkey_4327) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("wmem_strong_hash")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vkey_4327
		and target_0.getArgument(1) instanceof SizeofTypeOperator)
}

predicate func_1(Parameter vkey_4327, VariableAccess target_1) {
		target_1.getTarget()=vkey_4327
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_2(Function func, SizeofTypeOperator target_2) {
		target_2.getType() instanceof LongType
		and target_2.getValue()="32"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, DeclStmt target_3) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vcoherent_set_object_key_bytes_4328, Parameter vkey_4327, Function func, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcoherent_set_object_key_bytes_4328
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("g_bytes_new")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkey_4327
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof SizeofTypeOperator
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Variable vcoherent_set_object_key_bytes_4328, FunctionCall target_5) {
		target_5.getTarget().hasName("g_bytes_hash")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vcoherent_set_object_key_bytes_4328
}

from Function func, Variable vcoherent_set_object_key_bytes_4328, Parameter vkey_4327, VariableAccess target_1, SizeofTypeOperator target_2, DeclStmt target_3, ExprStmt target_4, FunctionCall target_5
where
not func_0(vkey_4327)
and func_1(vkey_4327, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(vcoherent_set_object_key_bytes_4328, vkey_4327, func, target_4)
and func_5(vcoherent_set_object_key_bytes_4328, target_5)
and vcoherent_set_object_key_bytes_4328.getType().hasName("GBytes *")
and vkey_4327.getType().hasName("gconstpointer")
and vcoherent_set_object_key_bytes_4328.getParentScope+() = func
and vkey_4327.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
