package azure.secure.iam

import data.azure.iam.data as d

default no_sub_owner = false

#1.21 Ensure that no custom subscription owner roles are created
no_sub_owner{
	count(d.iam_total_roles) == count(d.iam_total_roles) - count(d.iam_sub_owner)
}
deny[msg] {     
	iam_failed := d.iam_total_roles & d.iam_sub_owner
    count(iam_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'no_sub_owner' policy", [iam_failed])         
}

