/**
 * @name postgresql-cb2ae5741f2458a474ed3c31458d242e678ff229-get_row_security_policies
 * @id cpp/postgresql/cb2ae5741f2458a474ed3c31458d242e678ff229/get-row-security-policies
 * @description postgresql-cb2ae5741f2458a474ed3c31458d242e678ff229-src/backend/rewrite/rowsecurity.c-get_row_security_policies CVE-2023-39418
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vuser_id_112, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, VariableAccess target_0) {
		target_0.getTarget()=vmerge_permissive_policies_406
		and target_0.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("get_policies_for_relation")
		and target_0.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_0.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vuser_id_112
		and target_0.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmerge_restrictive_policies_407
}

/*predicate func_1(Variable vuser_id_112, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, VariableAccess target_1) {
		target_1.getTarget()=vmerge_restrictive_policies_407
		and target_1.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("get_policies_for_relation")
		and target_1.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_1.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vuser_id_112
		and target_1.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmerge_permissive_policies_406
}

*/
predicate func_2(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, VariableAccess target_2) {
		target_2.getTarget()=vmerge_permissive_policies_406
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmerge_restrictive_policies_407
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="1"
}

/*predicate func_3(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, VariableAccess target_3) {
		target_3.getTarget()=vmerge_restrictive_policies_407
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmerge_permissive_policies_406
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="1"
}

*/
predicate func_5(Variable vuser_id_112, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, VariableAccess target_5) {
		target_5.getTarget()=vmerge_permissive_policies_406
		and target_5.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("get_policies_for_relation")
		and target_5.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_5.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vuser_id_112
		and target_5.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmerge_restrictive_policies_407
}

/*predicate func_6(Variable vuser_id_112, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, VariableAccess target_6) {
		target_6.getTarget()=vmerge_restrictive_policies_407
		and target_6.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("get_policies_for_relation")
		and target_6.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_6.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vuser_id_112
		and target_6.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmerge_permissive_policies_406
}

*/
predicate func_8(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, VariableAccess target_8) {
		target_8.getTarget()=vmerge_permissive_policies_406
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmerge_restrictive_policies_407
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="1"
}

/*predicate func_9(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, VariableAccess target_9) {
		target_9.getTarget()=vmerge_restrictive_policies_407
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmerge_permissive_policies_406
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="1"
}

*/
/*predicate func_10(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, ExprStmt target_25, ExprStmt target_26, ExprStmt target_27, AddressOfExpr target_28, AddressOfExpr target_29, AddressOfExpr target_30, AddressOfExpr target_31, Literal target_10) {
		target_10.getValue()="1"
		and not target_10.getValue()="0"
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmerge_permissive_policies_406
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmerge_restrictive_policies_407
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_25.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_26.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_27.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_28.getOperand().(VariableAccess).getLocation().isBefore(target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_29.getOperand().(VariableAccess).getLocation())
		and target_30.getOperand().(VariableAccess).getLocation().isBefore(target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_31.getOperand().(VariableAccess).getLocation())
}

*/
predicate func_12(Variable vuser_id_112, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, VariableAccess target_12) {
		target_12.getTarget()=vmerge_permissive_policies_406
		and target_12.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("get_policies_for_relation")
		and target_12.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_12.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vuser_id_112
		and target_12.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmerge_restrictive_policies_407
}

/*predicate func_13(Variable vuser_id_112, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, VariableAccess target_13) {
		target_13.getTarget()=vmerge_restrictive_policies_407
		and target_13.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("get_policies_for_relation")
		and target_13.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_13.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vuser_id_112
		and target_13.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmerge_permissive_policies_406
}

*/
predicate func_15(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, VariableAccess target_15) {
		target_15.getTarget()=vmerge_permissive_policies_406
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmerge_restrictive_policies_407
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="0"
}

/*predicate func_16(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, VariableAccess target_16) {
		target_16.getTarget()=vmerge_restrictive_policies_407
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmerge_permissive_policies_406
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="0"
}

*/
/*predicate func_17(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, ExprStmt target_32, AddressOfExpr target_29, AddressOfExpr target_31, Literal target_17) {
		target_17.getValue()="0"
		and not target_17.getValue()="1"
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmerge_permissive_policies_406
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmerge_restrictive_policies_407
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_32.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_29.getOperand().(VariableAccess).getLocation().isBefore(target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_31.getOperand().(VariableAccess).getLocation().isBefore(target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
}

*/
predicate func_19(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, VariableAccess target_19) {
		target_19.getTarget()=vmerge_permissive_policies_406
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmerge_restrictive_policies_407
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="0"
}

/*predicate func_20(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, VariableAccess target_20) {
		target_20.getTarget()=vmerge_restrictive_policies_407
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmerge_permissive_policies_406
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="0"
}

*/
/*predicate func_21(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, ExprStmt target_33, PointerDereferenceExpr target_34, ExprStmt target_35, Literal target_21) {
		target_21.getValue()="0"
		and not target_21.getValue()="1"
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmerge_permissive_policies_406
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmerge_restrictive_policies_407
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_33.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getLocation().isBefore(target_34.getOperand().(VariableAccess).getLocation())
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_35.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

*/
predicate func_22(Parameter vrte_108, Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vuser_id_112, Variable vrel_114, EqualityOperation target_36, BitwiseAndExpr target_37, ExprStmt target_38, ExprStmt target_32, ExprStmt target_39, ExprStmt target_27, ExprStmt target_25) {
	exists(IfStmt target_22 |
		target_22.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="requiredPerms"
		and target_22.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrte_108
		and target_22.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="2"
		and target_22.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("get_policies_for_relation")
		and target_22.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_22.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vuser_id_112
		and target_22.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("List *")
		and target_22.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("List *")
		and target_22.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_22.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_22.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_22.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("List *")
		and target_22.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("List *")
		and target_22.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_22.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_22.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="1"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(9)=target_22
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_36
		and target_37.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_22.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_22.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_38.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_22.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_32.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_39.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_22.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_22.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_27.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_25.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_22.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_23(Variable vuser_id_112, Variable vrel_114, EqualityOperation target_36, ExprStmt target_27) {
	exists(ExprStmt target_23 |
		target_23.getExpr().(FunctionCall).getTarget().hasName("get_policies_for_relation")
		and target_23.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_23.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vuser_id_112
		and target_23.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("List *")
		and target_23.getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("List *")
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(12)=target_23
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_36
		and target_27.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_23.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_24(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, EqualityOperation target_36, ExprStmt target_40, ExprStmt target_33) {
	exists(ExprStmt target_24 |
		target_24.getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_24.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_24.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_24.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("List *")
		and target_24.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("List *")
		and target_24.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_24.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_24.getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="0"
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(13)=target_24
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_36
		and target_40.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_24.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_24.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_33.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_25(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, ExprStmt target_25) {
		target_25.getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_25.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_25.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_25.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmerge_permissive_policies_406
		and target_25.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmerge_restrictive_policies_407
		and target_25.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_25.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_25.getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="1"
}

predicate func_26(Variable vuser_id_112, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, ExprStmt target_26) {
		target_26.getExpr().(FunctionCall).getTarget().hasName("get_policies_for_relation")
		and target_26.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_26.getExpr().(FunctionCall).getArgument(1) instanceof EnumConstantAccess
		and target_26.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vuser_id_112
		and target_26.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmerge_permissive_policies_406
		and target_26.getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmerge_restrictive_policies_407
}

predicate func_27(Variable vuser_id_112, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, ExprStmt target_27) {
		target_27.getExpr().(FunctionCall).getTarget().hasName("get_policies_for_relation")
		and target_27.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_27.getExpr().(FunctionCall).getArgument(1) instanceof EnumConstantAccess
		and target_27.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vuser_id_112
		and target_27.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmerge_permissive_policies_406
		and target_27.getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmerge_restrictive_policies_407
}

predicate func_28(Variable vmerge_permissive_policies_406, AddressOfExpr target_28) {
		target_28.getOperand().(VariableAccess).getTarget()=vmerge_permissive_policies_406
}

predicate func_29(Variable vmerge_permissive_policies_406, AddressOfExpr target_29) {
		target_29.getOperand().(VariableAccess).getTarget()=vmerge_permissive_policies_406
}

predicate func_30(Variable vmerge_restrictive_policies_407, AddressOfExpr target_30) {
		target_30.getOperand().(VariableAccess).getTarget()=vmerge_restrictive_policies_407
}

predicate func_31(Variable vmerge_restrictive_policies_407, AddressOfExpr target_31) {
		target_31.getOperand().(VariableAccess).getTarget()=vmerge_restrictive_policies_407
}

predicate func_32(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, ExprStmt target_32) {
		target_32.getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_32.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_32.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_32.getExpr().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_32.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmerge_permissive_policies_406
		and target_32.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmerge_restrictive_policies_407
		and target_32.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_32.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_32.getExpr().(FunctionCall).getArgument(7) instanceof Literal
}

predicate func_33(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, ExprStmt target_33) {
		target_33.getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_33.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_33.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_33.getExpr().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_33.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmerge_permissive_policies_406
		and target_33.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmerge_restrictive_policies_407
		and target_33.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_33.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_33.getExpr().(FunctionCall).getArgument(7) instanceof Literal
}

predicate func_34(Parameter vwithCheckOptions_109, PointerDereferenceExpr target_34) {
		target_34.getOperand().(VariableAccess).getTarget()=vwithCheckOptions_109
}

predicate func_35(Variable vrel_114, ExprStmt target_35) {
		target_35.getExpr().(FunctionCall).getTarget().hasName("table_close")
		and target_35.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_35.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_36(EqualityOperation target_36) {
		target_36.getAnOperand().(VariableAccess).getTarget().getType().hasName("CmdType")
}

predicate func_37(Parameter vrte_108, BitwiseAndExpr target_37) {
		target_37.getLeftOperand().(PointerFieldAccess).getTarget().getName()="requiredPerms"
		and target_37.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrte_108
		and target_37.getRightOperand().(BinaryBitwiseOperation).getValue()="2"
}

predicate func_38(Parameter vrte_108, ExprStmt target_38) {
		target_38.getExpr().(FunctionCall).getTarget().hasName("setRuleCheckAsUser")
		and target_38.getExpr().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("List **")
		and target_38.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="checkAsUser"
		and target_38.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrte_108
}

predicate func_39(Variable vuser_id_112, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, ExprStmt target_39) {
		target_39.getExpr().(FunctionCall).getTarget().hasName("get_policies_for_relation")
		and target_39.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_39.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vuser_id_112
		and target_39.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmerge_permissive_policies_406
		and target_39.getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmerge_restrictive_policies_407
}

predicate func_40(Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, ExprStmt target_40) {
		target_40.getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_40.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_114
		and target_40.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_108
		and target_40.getExpr().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_40.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmerge_permissive_policies_406
		and target_40.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmerge_restrictive_policies_407
		and target_40.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_109
		and target_40.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_110
		and target_40.getExpr().(FunctionCall).getArgument(7) instanceof Literal
}

from Function func, Parameter vrte_108, Parameter vrt_index_108, Parameter vwithCheckOptions_109, Parameter vhasSubLinks_110, Variable vuser_id_112, Variable vrel_114, Variable vmerge_permissive_policies_406, Variable vmerge_restrictive_policies_407, VariableAccess target_0, VariableAccess target_2, VariableAccess target_5, VariableAccess target_8, VariableAccess target_12, VariableAccess target_15, VariableAccess target_19, ExprStmt target_25, ExprStmt target_26, ExprStmt target_27, AddressOfExpr target_28, AddressOfExpr target_29, AddressOfExpr target_30, AddressOfExpr target_31, ExprStmt target_32, ExprStmt target_33, PointerDereferenceExpr target_34, ExprStmt target_35, EqualityOperation target_36, BitwiseAndExpr target_37, ExprStmt target_38, ExprStmt target_39, ExprStmt target_40
where
func_0(vuser_id_112, vrel_114, vmerge_permissive_policies_406, vmerge_restrictive_policies_407, target_0)
and func_2(vrt_index_108, vwithCheckOptions_109, vhasSubLinks_110, vrel_114, vmerge_permissive_policies_406, vmerge_restrictive_policies_407, target_2)
and func_5(vuser_id_112, vrel_114, vmerge_permissive_policies_406, vmerge_restrictive_policies_407, target_5)
and func_8(vrt_index_108, vwithCheckOptions_109, vhasSubLinks_110, vrel_114, vmerge_permissive_policies_406, vmerge_restrictive_policies_407, target_8)
and func_12(vuser_id_112, vrel_114, vmerge_permissive_policies_406, vmerge_restrictive_policies_407, target_12)
and func_15(vrt_index_108, vwithCheckOptions_109, vhasSubLinks_110, vrel_114, vmerge_permissive_policies_406, vmerge_restrictive_policies_407, target_15)
and func_19(vrt_index_108, vwithCheckOptions_109, vhasSubLinks_110, vrel_114, vmerge_permissive_policies_406, vmerge_restrictive_policies_407, target_19)
and not func_22(vrte_108, vrt_index_108, vwithCheckOptions_109, vhasSubLinks_110, vuser_id_112, vrel_114, target_36, target_37, target_38, target_32, target_39, target_27, target_25)
and not func_23(vuser_id_112, vrel_114, target_36, target_27)
and not func_24(vrt_index_108, vwithCheckOptions_109, vhasSubLinks_110, vrel_114, target_36, target_40, target_33)
and func_25(vrt_index_108, vwithCheckOptions_109, vhasSubLinks_110, vrel_114, vmerge_permissive_policies_406, vmerge_restrictive_policies_407, target_25)
and func_26(vuser_id_112, vrel_114, vmerge_permissive_policies_406, vmerge_restrictive_policies_407, target_26)
and func_27(vuser_id_112, vrel_114, vmerge_permissive_policies_406, vmerge_restrictive_policies_407, target_27)
and func_28(vmerge_permissive_policies_406, target_28)
and func_29(vmerge_permissive_policies_406, target_29)
and func_30(vmerge_restrictive_policies_407, target_30)
and func_31(vmerge_restrictive_policies_407, target_31)
and func_32(vrt_index_108, vwithCheckOptions_109, vhasSubLinks_110, vrel_114, vmerge_permissive_policies_406, vmerge_restrictive_policies_407, target_32)
and func_33(vrt_index_108, vwithCheckOptions_109, vhasSubLinks_110, vrel_114, vmerge_permissive_policies_406, vmerge_restrictive_policies_407, target_33)
and func_34(vwithCheckOptions_109, target_34)
and func_35(vrel_114, target_35)
and func_36(target_36)
and func_37(vrte_108, target_37)
and func_38(vrte_108, target_38)
and func_39(vuser_id_112, vrel_114, vmerge_permissive_policies_406, vmerge_restrictive_policies_407, target_39)
and func_40(vrt_index_108, vwithCheckOptions_109, vhasSubLinks_110, vrel_114, vmerge_permissive_policies_406, vmerge_restrictive_policies_407, target_40)
and vrte_108.getType().hasName("RangeTblEntry *")
and vrt_index_108.getType().hasName("int")
and vwithCheckOptions_109.getType().hasName("List **")
and vhasSubLinks_110.getType().hasName("bool *")
and vuser_id_112.getType().hasName("Oid")
and vrel_114.getType().hasName("Relation")
and vmerge_permissive_policies_406.getType().hasName("List *")
and vmerge_restrictive_policies_407.getType().hasName("List *")
and vrte_108.getFunction() = func
and vrt_index_108.getFunction() = func
and vwithCheckOptions_109.getFunction() = func
and vhasSubLinks_110.getFunction() = func
and vuser_id_112.(LocalVariable).getFunction() = func
and vrel_114.(LocalVariable).getFunction() = func
and vmerge_permissive_policies_406.(LocalVariable).getFunction() = func
and vmerge_restrictive_policies_407.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
